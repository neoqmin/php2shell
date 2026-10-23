#!/usr/bin/env python3
"""Non-invasive local PHP2Shell exposure checker. Run it on the PHP server.

It only reads configuration files, package metadata, /proc and logs. It never
executes commands, never opens a network connection, and writes nothing outside
the report directory. Linux only: Debian/Ubuntu layout fully, RHEL layout
partially (no package version).

For every serving path (web server -> SAPI/FPM pool -> PHP build) it decides
whether the preconditions of CVE-2026-109618 / CVE-2026-109619 hold, and writes
an administrator report: report.json, report_ko.md, report.html.

Basis: PHP_취약점_동향_2026-10.md §2 (line numbers are cited in the report).
Exit codes: 0 = nothing reachable or undetermined, 1 = at least one reachable finding,
2 = error or no PHP serving path found, 3 = no reachable finding but some undetermined.
"""

from __future__ import annotations

import argparse
import glob
import gzip
import html
import json
import os
import re
import socket
import sys
import time
import zlib
from dataclasses import asdict, dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple
from urllib.parse import urlparse

VERSION = "1.0"
DOC = "PHP_취약점_동향_2026-10.md"

# Same table as php2shell_remote.py (PHP2Shell fixed releases, DOC §2.3).
FIXED = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}
BACKPORT_ONLY = {(7, 4), (8, 0), (8, 1)}  # DOC:69 source backports only
CVES = ("CVE-2026-109618", "CVE-2026-109619")
CVSS = "CVSS v4.0 9.2"
FIRST_SEEN = "2026-10-17"  # DOC:28 first exploitation attempt

# Built-in PHP defaults for the directives this checker evaluates.
DEFAULTS = {
    "memory_limit": "128M",
    "post_max_size": "8M",
    "upload_max_filesize": "2M",
    "session.upload_progress.enabled": "1",
    "expose_php": "1",
    "fatal_error_backtraces": "1",  # PHP 8.5+, DOC:53
}
WATCHED = tuple(DEFAULTS)

VERDICT_KO = {
    "reachable": "도달가능",
    "mitigated": "완화됨(임시)",
    "undetermined": "판정보류",
    "patched": "패치됨",
}
PRIO_KO = {"now": "즉시", "temp": "임시 완화", "hygiene": "정비", "check": "확인 필요"}

MAX_CONF_BYTES = 4 * 1024 * 1024
MAX_LOG_BYTES = 16 * 1024 * 1024
MAX_PHP_BYTES = 512 * 1024
MAX_WALK_FILES = 50000


# ---------------------------------------------------------------------------
# Read-only filesystem access (supports --root for offline/fixture analysis)
# ---------------------------------------------------------------------------

class Host:
    def __init__(self, root: str) -> None:
        root = os.path.abspath(root)
        self.prefix = "" if root == os.path.abspath(os.sep) else root
        self.files_read: List[str] = []
        self.denied: List[str] = []

    def real(self, path: str) -> str:
        if not self.prefix:
            return path
        # Resolve symlinks component by component so that absolute link targets
        # (e.g. conf.d/10-opcache.ini -> /etc/php/...) stay inside the copy.
        parts = [p for p in path.split("/") if p]
        done: List[str] = []
        hops = 0
        while parts:
            part = parts.pop(0)
            if part == "..":
                if done:
                    done.pop()
                continue
            cur = os.path.join(self.prefix, *(done + [part]))
            if os.path.islink(cur) and hops < 40:
                hops += 1
                target = os.readlink(cur).replace("\\", "/")
                if target.startswith("/"):
                    done = []
                parts = [p for p in target.split("/") if p and p != "."] + parts
                continue
            done.append(part)
        return os.path.join(self.prefix, *done)

    def logical(self, real: str) -> str:
        if not self.prefix:
            return real
        return "/" + os.path.relpath(real, self.prefix).replace(os.sep, "/")

    def glob(self, pattern: str) -> List[str]:
        if not self.prefix:
            return sorted(glob.glob(pattern))
        real = os.path.join(glob.escape(self.prefix), *[p for p in pattern.split("/") if p])
        return sorted(self.logical(m) for m in glob.glob(real))

    def exists(self, path: str) -> bool:
        return os.path.exists(self.real(path))

    def isdir(self, path: str) -> bool:
        return os.path.isdir(self.real(path))

    def mtime(self, path: str) -> Optional[float]:
        try:
            return os.stat(self.real(path)).st_mtime
        except OSError:
            return None

    def _note(self, path: str) -> None:
        if path not in self.files_read:
            self.files_read.append(path)

    def read_text(self, path: str, limit: int = MAX_CONF_BYTES) -> Optional[str]:
        try:
            with open(self.real(path), "rb") as f:
                data = f.read(limit)
        except PermissionError:
            if path not in self.denied:
                self.denied.append(path)
            return None
        except OSError:
            return None
        self._note(path)
        return data.decode("utf-8", errors="replace")

    def read_log(self, path: str, limit: int = MAX_LOG_BYTES) -> Optional[str]:
        """Tail of a plain log, or the head of a rotated .gz log."""
        try:
            if path.endswith(".gz"):
                with gzip.open(self.real(path), "rb") as f:
                    data = f.read(limit)
            else:
                with open(self.real(path), "rb") as f:
                    f.seek(0, os.SEEK_END)
                    f.seek(max(0, f.tell() - limit))
                    data = f.read(limit)
        except PermissionError:
            if path not in self.denied:
                self.denied.append(path)
            return None
        except (OSError, EOFError, zlib.error):
            return None
        self._note(path)
        return data.decode("utf-8", errors="replace")

    def walk_files(self, top: str) -> Iterator[str]:
        for dirpath, _dirs, files in os.walk(self.real(top)):
            for name in files:
                yield self.logical(os.path.join(dirpath, name))


def loc(path: str, line: int) -> str:
    return f"{path}:{line}"


# ---------------------------------------------------------------------------
# php.ini / php-fpm.conf parsing
# ---------------------------------------------------------------------------

def clean_ini_value(value: str) -> str:
    value = value.strip()
    if value[:1] in ("'", '"'):
        end = value.find(value[0], 1)
        return value[1:end] if end > 0 else value[1:]
    return value.split(";", 1)[0].strip()


def parse_ini(text: str) -> Iterator[Tuple[Optional[str], Optional[str], str, int]]:
    """Yields (section, key, value, line). Section headers yield key=None."""
    section = None
    for no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line[0] in ";#":
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            yield section, None, "", no
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            yield section, key.strip(), clean_ini_value(value), no


def ini_bool(value: Optional[str]) -> Optional[bool]:
    s = (value or "").strip().lower()
    if s in ("1", "on", "true", "yes"):
        return True
    if s in ("0", "off", "false", "no", "none", ""):
        return False
    return None


def fmt_size(n: int) -> str:
    if n >= 1024 ** 2 and n % 1024 ** 2 == 0:
        return f"{n // 1024 ** 2}M"
    return f"{max(1, n // 1024)}K"


def ini_bytes(value: Optional[str]) -> Optional[int]:
    m = re.match(r"^\s*(-?\d+)\s*([kmg]?)\s*$", (value or "").lower())
    if not m:
        return None
    n = int(m.group(1))
    if n < 0:
        return -1
    return n * {"": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}[m.group(2)]


@dataclass
class Setting:
    key: str
    value: str
    origin: str      # default | php.ini | pool | nginx | apache
    location: str    # file:line, or "PHP 기본값"
    locked: bool = False  # php_admin_* (cannot be overridden by the app)


@dataclass
class Layer:
    origin: str
    entries: List[Setting] = field(default_factory=list)


def resolve(layers: List[Layer]) -> Tuple[Dict[str, Setting], List[str]]:
    eff = {k: Setting(k, v, "default", "PHP 기본값") for k, v in DEFAULTS.items()}
    notes: List[str] = []
    for layer in layers:
        for s in layer.entries:
            if s.key not in eff:
                continue
            cur = eff[s.key]
            if cur.locked and not s.locked:
                notes.append(f"{s.location}의 {s.key}={s.value}는 {cur.location}의 php_admin 값에 막혀 무시됩니다.")
                continue
            eff[s.key] = s
    return eff, notes


def system_ini_layer(host: Host, files: List[str]) -> Layer:
    layer = Layer("php.ini")
    for path in files:
        text = host.read_text(path)
        if text is None:
            continue
        for section, key, value, no in parse_ini(text):
            if key and key in DEFAULTS:
                if section and section.upper().startswith(("HOST=", "PATH=")):
                    continue  # per-host/path sections are CGI/FastCGI only; not modelled
                layer.entries.append(Setting(key, value, "php.ini", loc(path, no)))
    return layer


@dataclass
class Pool:
    name: str
    file: str
    line: int
    listen: Optional[str] = None
    layer: Layer = field(default_factory=lambda: Layer("pool"))


POOL_PHP_RE = re.compile(r"^(php_(?:admin_)?(?:value|flag))\[(.+)\]$")


def parse_fpm(host: Host, conf: str) -> Tuple[List[Pool], List[str]]:
    """Returns (pools, pool files). Sections with the same name across files merge, later wins."""
    pools: Dict[str, Pool] = {}
    files: List[str] = []
    base = conf.rsplit("/", 1)[0]
    # Relative includes resolve against the FPM prefix (/usr/local for "/usr/local/etc/php-fpm.conf").
    prefix = base[:-4] if base.endswith("/etc") else base
    _parse_fpm_file(host, conf, base, prefix, pools, files, 0)
    return list(pools.values()), files


def _parse_fpm_file(host: Host, conf: str, base: str, prefix: str,
                    pools: Dict[str, Pool], files: List[str], depth: int) -> None:
    text = host.read_text(conf)
    files.append(conf)
    if text is None or depth > 4:
        return
    current: Optional[Pool] = None
    for section, key, value, no in parse_ini(text):
        if key is None:
            if section == "global" or not section:
                current = None
            else:
                current = pools.setdefault(section, Pool(section, conf, no))
            continue
        if key == "include":
            candidates = [value] if value.startswith("/") else [f"{prefix}/{value}", f"{base}/{value}"]
            for pattern in candidates:
                matches = host.glob(pattern)
                for inc in matches:
                    _parse_fpm_file(host, inc, base, prefix, pools, files, depth + 1)
                if matches:
                    break
            continue
        if current is None:
            continue
        if key == "listen":
            current.listen = value.replace("$pool", current.name)
            continue
        m = POOL_PHP_RE.match(key)
        if m and m.group(2) in DEFAULTS:
            current.layer.entries.append(
                Setting(m.group(2), value, "pool", loc(conf, no), locked="admin" in m.group(1))
            )


# ---------------------------------------------------------------------------
# nginx parsing
# ---------------------------------------------------------------------------

@dataclass
class NDir:
    name: str
    args: List[str]
    file: str
    line: int
    block: Optional[List["NDir"]] = None


NGINX_ESCAPES = {"n": "\n", "t": "\t", "r": "\r"}


def nginx_tokens(text: str) -> Iterator[Tuple[str, int, bool]]:
    """Yields (token, line, quoted). Quoted tokens are never structural."""
    i, n, line = 0, len(text), 1
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
        elif c.isspace():
            i += 1
        elif c == "#":
            while i < n and text[i] != "\n":
                i += 1
        elif c in "{};":
            yield c, line, False
            i += 1
        elif c in "\"'":
            start_line, j, buf = line, i + 1, []
            while j < n and text[j] != c:
                ch = text[j]
                if ch == "\\" and j + 1 < n:
                    j += 1
                    ch = NGINX_ESCAPES.get(text[j], text[j])
                if text[j] == "\n":
                    line += 1
                buf.append(ch)
                j += 1
            yield "".join(buf), start_line, True
            i = j + 1
        else:
            j = i
            while j < n and not text[j].isspace() and text[j] not in "{};":
                j += 1
            yield text[i:j], line, False
            i = j


def parse_nginx(host: Host, path: str, depth: int = 0) -> List[NDir]:
    text = host.read_text(path)
    if text is None or depth > 8:
        return []
    tokens = list(nginx_tokens(text))
    pos = 0

    def block() -> List[NDir]:
        nonlocal pos
        out: List[NDir] = []
        words: List[Tuple[str, int]] = []
        while pos < len(tokens):
            tok, line, quoted = tokens[pos]
            pos += 1
            if quoted:
                words.append((tok, line))
            elif tok == ";" and words:
                name, args = words[0][0], [w for w, _ in words[1:]]
                if name == "include" and args:
                    pattern = args[0] if args[0].startswith("/") else f"/etc/nginx/{args[0]}"
                    for inc in host.glob(pattern):
                        out.extend(parse_nginx(host, inc, depth + 1))
                else:
                    out.append(NDir(name, args, path, words[0][1]))
                words = []
            elif tok == "{" and words:
                out.append(NDir(words[0][0], [w for w, _ in words[1:]], path, words[0][1], block()))
                words = []
            elif tok == "}":
                return out
            elif tok not in (";", "{"):
                words.append((tok, line))
        return out

    return block()


@dataclass
class Frontend:
    kind: str               # nginx | apache
    names: List[str]
    location: str           # file:line of server/vhost
    route: str              # "location ~ \.php$ (file:line)" or handler
    target: Optional[str]   # fastcgi address (normalized) or None for mod_php
    roots: List[str]
    body_limit: Optional[str] = None
    body_limit_loc: Optional[str] = None
    layer: Layer = field(default_factory=lambda: Layer("nginx"))
    ssl_certs: List[Tuple[str, str]] = field(default_factory=list)  # (cert file, directive loc)
    chain_file: Optional[str] = None  # Apache SSLCertificateChainFile


def norm_addr(addr: Optional[str]) -> Optional[str]:
    if not addr:
        return None
    a = addr.strip()
    if a.startswith("unix:"):
        a = a[5:]
    if a.startswith("/"):
        a = a.split("|", 1)[0]
        if a.startswith("/var/run/"):
            a = a[4:]  # /var/run is a symlink to /run on every current distribution
        return "unix:" + a
    a = a.split("|", 1)[0].replace("fcgi://", "")
    port = a.rsplit(":", 1)[-1] if ":" in a else a
    return "tcp:" + port.strip("/") if port.strip("/").isdigit() else "tcp:" + a


def canon_addr(host: Host, addr: Optional[str]) -> Optional[str]:
    """norm_addr plus symlink resolution of unix sockets (e.g. php-fpm.sock alternatives)."""
    a = norm_addr(addr)
    if not a or not a.startswith("unix:"):
        return a
    path = a[5:]
    real = host.real(path) if host.prefix else (os.path.realpath(path) if os.path.lexists(path) else path)
    return norm_addr("unix:" + host.logical(real)) if host.prefix else norm_addr("unix:" + real)


def php_value_lines(raw: str) -> List[Tuple[str, str]]:
    out = []
    for part in raw.splitlines():
        if "=" in part:
            k, v = part.split("=", 1)
            out.append((k.strip(), v.strip().strip('"\'')))
    return out


def nginx_frontends(host: Host) -> List[Frontend]:
    top = parse_nginx(host, "/etc/nginx/nginx.conf")
    fronts: List[Frontend] = []
    for http in (d for d in top if d.name == "http" and d.block is not None):
        upstreams = {
            d.args[0]: [norm_addr(s.args[0]) for s in d.block or [] if s.name == "server" and s.args]
            for d in http.block if d.name == "upstream" and d.args
        }
        for srv in (d for d in http.block if d.name == "server" and d.block is not None):
            _walk_server(srv, [http, srv], upstreams, fronts)
    return fronts


def _nearest(chain: List[NDir], name: str) -> Optional[NDir]:
    for blk in reversed(chain):
        for d in blk.block or []:
            if d.name == name:
                return d
    return None


def _walk_server(node: NDir, chain: List[NDir], upstreams, fronts: List[Frontend]) -> None:
    srv = chain[1]
    for d in node.block or []:
        if d.name in ("location", "if") and d.block is not None:
            _walk_server(d, chain + [d], upstreams, fronts)
        if d.name != "fastcgi_pass" or not d.args:
            continue
        names = next((x.args for x in srv.block or [] if x.name == "server_name"), []) or ["(server_name 없음)"]
        root = _nearest(chain, "root")
        body = _nearest(chain, "client_max_body_size")
        fe = Frontend(
            kind="nginx",
            names=names,
            location=loc(srv.file, srv.line),
            route=(f"location {' '.join(node.args)} ({loc(node.file, node.line)})" if node is not srv
                   else f"server ({loc(srv.file, srv.line)})"),
            target=None,
            roots=[root.args[0]] if root and root.args else [],
            body_limit=body.args[0] if body and body.args else None,
            body_limit_loc=loc(body.file, body.line) if body else None,
        )
        targets = upstreams.get(d.args[0]) or [norm_addr(d.args[0])]
        fe.target = targets[0]
        # fastcgi_param is an array directive: the nearest level that defines any wins.
        for blk in reversed(chain):
            params = [x for x in blk.block or [] if x.name == "fastcgi_param" and len(x.args) >= 2]
            if params:
                for p in params:
                    if p.args[0] in ("PHP_VALUE", "PHP_ADMIN_VALUE"):
                        for k, v in php_value_lines(p.args[1]):
                            if k in DEFAULTS:
                                fe.layer.entries.append(Setting(
                                    k, v, "nginx", loc(p.file, p.line), locked=p.args[0] == "PHP_ADMIN_VALUE"))
                break
        for x in srv.block or []:
            if x.name == "ssl_certificate" and x.args:
                fe.ssl_certs.append((x.args[0], loc(x.file, x.line)))
        fronts.append(fe)


# ---------------------------------------------------------------------------
# Apache parsing (line based)
# ---------------------------------------------------------------------------

@dataclass
class ApacheInfo:
    vhosts: List[Frontend] = field(default_factory=list)
    php_layer: Layer = field(default_factory=lambda: Layer("apache"))
    global_target: Optional[str] = None
    global_guarded: bool = False  # declared inside <IfModule !mod_php...>
    global_route: str = ""
    global_roots: List[str] = field(default_factory=list)
    php_modules: List[str] = field(default_factory=list)  # LoadModule php* lines (file:line)
    found: bool = False


APACHE_PHP_RE = re.compile(r"^(php_(?:admin_)?(?:value|flag))\s+(\S+)\s+(.+)$", re.I)
APACHE_FCGI_RE = re.compile(r"proxy:(unix:[^|\"\s]+|fcgi://[^\"\s/]+)", re.I)


def parse_apache(host: Host) -> ApacheInfo:
    info = ApacheInfo()
    for server_root, conf in (("/etc/apache2", "/etc/apache2/apache2.conf"),
                              ("/etc/httpd", "/etc/httpd/conf/httpd.conf")):
        if host.exists(conf):
            info.found = True
            _apache_file(host, server_root, conf, info, [None], 0)
    # Handlers declared outside any VirtualHost (Debian "a2enconf php8.x-fpm") apply to every vhost.
    mod_php = info.php_modules or host.glob("/etc/apache2/mods-enabled/php*.load")
    if info.global_guarded and mod_php:
        info.global_target, info.global_route = None, ""
    if not info.vhosts and info.found:
        info.vhosts.append(Frontend("apache", ["(전역)"], "apache 전역 설정", info.global_route or "전역",
                                    None, list(info.global_roots)))
    for vh in info.vhosts:
        if vh.target is None and info.global_target:
            vh.target = info.global_target
            vh.route = info.global_route
        if not vh.roots:
            vh.roots = list(info.global_roots)
    return info


def _apache_file(host: Host, server_root: str, path: str, info: ApacheInfo, stack, depth: int,
                 ifmods: Optional[List[bool]] = None) -> None:
    text = host.read_text(path)
    if text is None or depth > 8:
        return
    ifmods = [] if ifmods is None else ifmods  # True = "<IfModule !...php...>" block
    for no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        low = line.lower()
        if low.startswith("<ifmodule"):
            ifmods.append(bool(re.match(r"<ifmodule\s+!\s*\S*php", low)))
            continue
        if low.startswith("</ifmodule"):
            if ifmods:
                ifmods.pop()
            continue
        vh: Optional[Frontend] = stack[-1]
        if low.startswith("<virtualhost"):
            fe = Frontend("apache", [], loc(path, no), f"VirtualHost ({loc(path, no)})", None, [])
            info.vhosts.append(fe)
            stack.append(fe)
            continue
        if low.startswith("</virtualhost"):
            if len(stack) > 1:
                stack.pop()
            continue
        parts = line.split(None, 1)
        name, rest = parts[0].lower(), (parts[1] if len(parts) > 1 else "")
        if name in ("include", "includeoptional") and rest:
            pattern = rest.strip("\"'")
            if not pattern.startswith("/"):
                pattern = f"{server_root}/{pattern}"
            for inc in host.glob(pattern):
                _apache_file(host, server_root, inc, info, stack, depth + 1, ifmods)
            continue
        m = APACHE_PHP_RE.match(line)
        if m and m.group(2) in DEFAULTS:
            info.php_layer.entries.append(Setting(
                m.group(2), clean_ini_value(m.group(3)), "apache", loc(path, no),
                locked="admin" in m.group(1).lower()))
            continue
        if name == "loadmodule" and re.search(r"php\d*_module|libphp", rest):
            info.php_modules.append(loc(path, no) + " " + rest)
            continue
        if vh is None:
            if name == "documentroot":
                info.global_roots.append(rest.strip("\"'"))
            elif name in ("sethandler", "proxypassmatch"):
                fm = APACHE_FCGI_RE.search(line)
                if fm:
                    info.global_target = norm_addr(fm.group(1))
                    info.global_route = f"{parts[0]} ({loc(path, no)})"
                    info.global_guarded = any(ifmods)
            continue
        if name in ("servername", "serveralias"):
            vh.names.extend(rest.split())
        elif name == "documentroot":
            vh.roots.append(rest.strip("\"'"))
        elif name == "sslcertificatefile":
            vh.ssl_certs.append((rest.strip("\"'"), loc(path, no)))
        elif name == "sslcertificatechainfile":
            vh.chain_file = rest.strip("\"'")
        elif name in ("sethandler", "proxypassmatch"):
            fm = APACHE_FCGI_RE.search(line)
            if fm:
                vh.target = norm_addr(fm.group(1))
                vh.route = f"{parts[0]} ({loc(path, no)})"


# ---------------------------------------------------------------------------
# Packages, processes
# ---------------------------------------------------------------------------

def dpkg_installed(host: Host) -> Dict[str, str]:
    text = host.read_text("/var/lib/dpkg/status", limit=64 * 1024 * 1024)
    pkgs: Dict[str, str] = {}
    for para in (text or "").split("\n\n"):
        fields = dict(re.findall(r"^([A-Za-z-]+):\s*(.*)$", para, re.M))
        if "installed" in fields.get("Status", "").split() and fields.get("Package", "").startswith(("php", "libapache2-mod-php")):
            pkgs[fields["Package"]] = fields.get("Version", "")
    return pkgs


def upstream_version(deb_version: str) -> Optional[str]:
    m = re.match(r"^(?:\d+:)?(\d+\.\d+\.\d+)", deb_version)
    return m.group(1) if m else None


def package_origin(deb_version: str) -> str:
    if "sury" in deb_version:
        return "Ondřej Surý PPA (deb.sury.org)"
    if re.search(r"ubuntu|deb\d+u|\+deb", deb_version):
        return "배포판 공식 패키지"
    return "출처 미상"


def changelog_has_fix(host: Host, pkgs: List[str]) -> Tuple[Optional[bool], Optional[str]]:
    for pkg in pkgs:
        for name in ("changelog.Debian.gz", "changelog.gz"):
            path = f"/usr/share/doc/{pkg}/{name}"
            if host.exists(path):
                text = host.read_log(path, limit=8 * 1024 * 1024)
                if text is None:
                    return None, path
                return all(c in text for c in CVES), path
    return None, None


@dataclass
class Proc:
    pid: int
    cmdline: str
    comm: str
    start: Optional[float]


def scan_procs(host: Host) -> Optional[List[Proc]]:
    if not host.isdir("/proc"):
        return None
    btime = None
    stat = host.read_text("/proc/stat")
    if stat:
        m = re.search(r"^btime\s+(\d+)", stat, re.M)
        btime = int(m.group(1)) if m else None
    try:
        hz = os.sysconf("SC_CLK_TCK")
    except (AttributeError, ValueError, OSError):
        hz = 100
    procs = []
    for d in host.glob("/proc/[0-9]*"):
        try:
            with open(host.real(d + "/cmdline"), "rb") as f:
                cmd = f.read(4096).replace(b"\0", b" ").decode("utf-8", "replace").strip()
            with open(host.real(d + "/stat"), "r", encoding="utf-8", errors="replace") as f:
                st = f.read(4096)
        except OSError:
            continue
        comm = st[st.find("(") + 1:st.rfind(")")]
        fields = st[st.rfind(")") + 2:].split()
        start = None
        if btime is not None and len(fields) > 19 and fields[19].isdigit():
            start = btime + int(fields[19]) / hz
        procs.append(Proc(int(d.rsplit("/", 1)[1]), cmd, comm, start))
    return procs


# ---------------------------------------------------------------------------
# Serving units
# ---------------------------------------------------------------------------

@dataclass
class Unit:
    id: str
    sapi: str                       # fpm | apache2handler
    branch: Optional[Tuple[int, int]]
    package: Optional[str] = None
    package_version: Optional[str] = None
    version: Optional[str] = None
    version_source: Optional[str] = None
    pool: Optional[Pool] = None
    frontends: List[Frontend] = field(default_factory=list)
    layers: List[Layer] = field(default_factory=list)
    config_files: List[str] = field(default_factory=list)
    running: Optional[bool] = None
    started: Optional[float] = None
    service: str = ""
    settings: Dict[str, Setting] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)
    incomplete: List[str] = field(default_factory=list)

    @property
    def branch_str(self) -> str:
        return ".".join(map(str, self.branch)) if self.branch else "?"

    @property
    def label(self) -> str:
        if self.sapi == "fpm":
            return f"PHP {self.branch_str} FPM pool [{self.pool.name if self.pool else '?'}]"
        return f"PHP {self.branch_str} Apache mod_php"


def branch_of(text: str) -> Optional[Tuple[int, int]]:
    m = re.search(r"(\d+)\.(\d+)", text)
    return (int(m.group(1)), int(m.group(2))) if m else None


def build_units(host: Host, pkgs: Dict[str, str], procs: Optional[List[Proc]],
                fronts: List[Frontend], apache: ApacheInfo) -> List[Unit]:
    units: List[Unit] = []

    # PHP-FPM, Debian layout then RHEL layout.
    fpm_confs = [(c, branch_of(c), c.rsplit("/", 1)[0]) for c in host.glob("/etc/php/*/fpm/php-fpm.conf")]
    if host.exists("/etc/php-fpm.conf"):
        fpm_confs.append(("/etc/php-fpm.conf", None, None))
    for conf, branch, sapi_dir in fpm_confs:
        if sapi_dir:
            ini_files = [f"{sapi_dir}/php.ini"] + host.glob(f"{sapi_dir}/conf.d/*.ini")
            package, service = f"php{branch[0]}.{branch[1]}-fpm", f"php{branch[0]}.{branch[1]}-fpm"
        else:
            ini_files = ["/etc/php.ini"] + host.glob("/etc/php.d/*.ini")
            package, service = None, "php-fpm"
        if package and pkgs and package not in pkgs:
            continue  # leftover configuration of a removed package
        sys_layer = system_ini_layer(host, ini_files)
        master = None
        if procs is not None:
            master = next((p for p in procs if "php-fpm: master process" in p.cmdline and conf in p.cmdline), None)
            if master is None and not sapi_dir:
                master = next((p for p in procs if "php-fpm: master process" in p.cmdline), None)
        pools, pool_files = parse_fpm(host, conf)
        for pool in pools:
            u = Unit(f"U{len(units) + 1:02d}", "fpm", branch, package=package, pool=pool, service=service)
            u.layers = [sys_layer, pool.layer]
            u.config_files = [f for f in ini_files if host.exists(f)] + pool_files
            u.running = None if procs is None else master is not None
            u.started = master.start if master else None
            addr = canon_addr(host, pool.listen)
            u.frontends = [f for f in fronts if f.target and canon_addr(host, f.target) == addr]
            units.append(u)

    # Apache mod_php.
    for load in host.glob("/etc/apache2/mods-enabled/php*.load"):
        branch = branch_of(load.rsplit("/", 1)[1])
        sapi_dir = f"/etc/php/{branch[0]}.{branch[1]}/apache2" if branch else None
        ini_files = ([f"{sapi_dir}/php.ini"] + host.glob(f"{sapi_dir}/conf.d/*.ini")) if sapi_dir else []
        # Official php:*-apache images load "php.load" and keep the build version in a header file.
        header_version = None
        if branch is None and host.exists("/usr/local/include/php/main/php_version.h"):
            m = re.search(r'#define\s+PHP_VERSION\s+"(\d+\.\d+\.\d+)',
                          host.read_text("/usr/local/include/php/main/php_version.h") or "")
            if m:
                header_version = m.group(1)
                branch = branch_of(header_version)
                ini_files = ["/usr/local/etc/php/php.ini"] + host.glob("/usr/local/etc/php/conf.d/*.ini")
        u = Unit(f"U{len(units) + 1:02d}", "apache2handler", branch,
                 package=f"libapache2-mod-php{branch[0]}.{branch[1]}" if branch else None, service="apache2")
        u.layers = [system_ini_layer(host, ini_files), apache.php_layer]
        u.config_files = [f for f in ini_files if host.exists(f)] + [load]
        u.frontends = [v for v in apache.vhosts if v.target is None]
        if procs is not None:
            masters = [p for p in procs if p.comm in ("apache2", "httpd") and p.start]
            u.running = bool(masters)
            u.started = min(p.start for p in masters) if masters else None
        if header_version:
            u.package, u.service = None, ""
            u.version = header_version
            u.version_source = "헤더 파일 /usr/local/include/php/main/php_version.h (공식 Docker 이미지)"
        units.append(u)

    # Apache proxy_fcgi vhosts route to FPM pools like nginx does.
    for u in units:
        if u.sapi == "fpm" and u.pool:
            addr = canon_addr(host, u.pool.listen)
            u.frontends += [v for v in apache.vhosts if v.target and canon_addr(host, v.target) == addr]

    for u in units:
        if u.package and u.package in pkgs:
            u.package_version = pkgs[u.package]
            u.version = upstream_version(pkgs[u.package])
            u.version_source = f"dpkg: {u.package} {pkgs[u.package]}"
        for fe in u.frontends:
            u.layers.append(fe.layer)
        u.settings, notes = resolve(u.layers)
        u.notes.extend(notes)
        u.incomplete = [f for f in u.config_files if f in host.denied]
    return units


# ---------------------------------------------------------------------------
# Webroot, logs, TLS
# ---------------------------------------------------------------------------

INI_SET_RE = re.compile(
    r"ini_set\s*\(\s*['\"](memory_limit|session\.upload_progress\.enabled|post_max_size)['\"]\s*,\s*([^)]{0,60})\)")


@dataclass
class WebrootScan:
    root: str
    user_ini: List[Setting] = field(default_factory=list)
    ini_set: List[Setting] = field(default_factory=list)
    recent_php: List[Tuple[str, float]] = field(default_factory=list)
    recent_total: int = 0
    files_seen: int = 0
    truncated: bool = False


def scan_webroot(host: Host, root: str, since: float) -> WebrootScan:
    ws = WebrootScan(root)
    for path in host.walk_files(root):
        ws.files_seen += 1
        if ws.files_seen > MAX_WALK_FILES:
            ws.truncated = True
            break
        base = path.rsplit("/", 1)[-1]
        if base in (".user.ini", ".htaccess"):
            text = host.read_text(path) or ""
            for no, raw in enumerate(text.splitlines(), 1):
                line = raw.strip()
                if base == ".user.ini" and "=" in line and not line.startswith(";"):
                    k, v = line.split("=", 1)
                    if k.strip() in DEFAULTS:
                        ws.user_ini.append(Setting(k.strip(), clean_ini_value(v), base, loc(path, no)))
                m = APACHE_PHP_RE.match(line) if base == ".htaccess" else None
                if m and m.group(2) in DEFAULTS:
                    ws.user_ini.append(Setting(m.group(2), clean_ini_value(m.group(3)), base, loc(path, no)))
        elif base.endswith(".php"):
            mt = host.mtime(path)
            if mt is not None and mt >= since:
                ws.recent_total += 1
                ws.recent_php.append((path, mt))
            text = host.read_text(path, limit=MAX_PHP_BYTES)
            if text and "ini_set" in text:
                for m in INI_SET_RE.finditer(text):
                    no = text.count("\n", 0, m.start()) + 1
                    ws.ini_set.append(Setting(m.group(1), m.group(2).strip().strip("'\""), "ini_set", loc(path, no)))
    ws.recent_php.sort(key=lambda x: -x[1])
    ws.recent_php = ws.recent_php[:30]
    return ws


LOG_GLOBS = [
    "/var/log/php*-fpm.log*", "/var/log/php-fpm/*.log*", "/var/log/nginx/error.log*",
    "/var/log/apache2/error.log*", "/var/log/httpd/error_log*",
    "/var/log/syslog*", "/var/log/kern.log*", "/var/log/messages*",
]
LOG_PATTERNS = {
    "워커 비정상 종료(signal)": re.compile(r"exited on signal (?:11|6|7|4)\b|SIGSEGV|SIGBUS|SIGABRT", re.I),
    "PHP 프로세스 segfault": re.compile(r"(?:php|php-fpm|apache2|httpd)\S*\[\d+\]: segfault at|segfault at \S+ .* in (?:php|libphp)", re.I),
    "메모리 한도 초과 fatal": re.compile(r"Allowed memory size of \d+ bytes exhausted", re.I),
}


@dataclass
class LogHit:
    file: str
    category: str
    count: int
    samples: List[str]


def scan_logs(host: Host) -> List[LogHit]:
    hits: List[LogHit] = []
    seen = set()
    for pattern in LOG_GLOBS:
        for path in host.glob(pattern):
            if path in seen:
                continue
            seen.add(path)
            text = host.read_log(path)
            if not text:
                continue
            # System-wide logs only count kernel segfault lines; signal/OOM wording there is unrelated noise.
            system_log = any(x in path for x in ("syslog", "kern.log", "messages"))
            for cat, rx in LOG_PATTERNS.items():
                if system_log and not cat.startswith("PHP 프로세스"):
                    continue
                matched = [ln for ln in text.splitlines() if rx.search(ln)]
                if matched:
                    hits.append(LogHit(path, cat, len(matched), [m[:240] for m in matched[-3:]]))
    return hits


def cert_count(host: Host, path: str) -> Optional[int]:
    text = host.read_text(path, limit=1024 * 1024)
    return None if text is None else text.count("-----BEGIN CERTIFICATE-----")


# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    id: str
    cve: str
    unit: str
    component: str
    severity: str
    fixed_version: str
    verdict: str
    verdict_ko: str
    confidence: str
    condition: str
    rationale: str
    evidence_path: List[str]
    notes: List[str] = field(default_factory=list)


@dataclass
class Remediation:
    priority: str
    title: str
    problem: str
    current: str
    location: str
    fix: str
    verify: str
    impact: str = ""
    refs: str = ""
    units: List[str] = field(default_factory=list)


def parse_version(v: str) -> Tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def version_status(u: Unit, host: Host) -> Tuple[str, str]:
    """Returns (status, explanation). status: patched | vulnerable | eol | backport_only | unknown."""
    if u.branch is None:
        return "unknown", "PHP 버전을 확인하지 못했습니다(RHEL 계열 또는 패키지 정보 없음)."
    fixed = FIXED.get(u.branch)
    if u.version and fixed and parse_version(u.version) >= fixed:
        return "patched", f"{u.version} ≥ 수정 버전 {'.'.join(map(str, fixed))}"
    pkgs = [p for p in (u.package, f"php{u.branch_str}-common") if p]
    has_fix, path = changelog_has_fix(host, pkgs)
    if has_fix:
        return "patched", f"패키지 changelog({path})에 {', '.join(CVES)} 백포트 기록이 있습니다."
    cl = f" changelog({path})에 CVE 백포트 기록 없음." if has_fix is False else ""
    if u.branch < (7, 4):
        return "eol", f"PHP {u.branch_str}는 EOL이며 PHP2Shell 패치가 존재하지 않습니다(소스 백포트 없음, {DOC}:70).{cl}"
    if u.branch in BACKPORT_ONLY:
        return "backport_only", f"PHP {u.branch_str}는 공식 수정 릴리스가 없고 소스 백포트만 있습니다({DOC}:69).{cl}"
    if fixed is None:
        return "unknown", f"PHP {u.branch_str}는 수정 기준표에 없는 브랜치입니다."
    if not u.version:
        return "unknown", "패키지 버전을 확인하지 못했습니다."
    return "vulnerable", f"{u.version} < 수정 버전 {'.'.join(map(str, fixed))}.{cl}"


RESTART_NOTE = "설정 파일이 서비스 시작 이후 수정됐습니다. 재시작·리로드로 반영됐는지 확인할 수 없습니다(파일 mtime 기준 추정, DOC:108)."


def pending_restart(u: Unit, host: Host, setting: Setting) -> bool:
    if u.started is None or ":" not in setting.location:
        return False
    mt = host.mtime(setting.location.rsplit(":", 1)[0])
    return mt is not None and mt > u.started


def base_path(u: Unit) -> List[str]:
    path = []
    if u.frontends:
        fe = u.frontends[0]
        more = f" 외 {len(u.frontends) - 1}개" if len(u.frontends) > 1 else ""
        path.append(f"{fe.kind} {' '.join(fe.names[:3])} ({fe.location}){more}")
        path.append(fe.route)
        if fe.target:
            path.append(f"→ {fe.target}")
    else:
        path.append("웹서버 연결 미확인")
    if u.pool:
        path.append(f"FPM pool [{u.pool.name}] ({loc(u.pool.file, u.pool.line)}) listen={u.pool.listen}")
    path.append(f"PHP {u.version or u.branch_str} ({u.version_source or '버전 출처 없음'})")
    return path


def loosens(s: Setting) -> bool:
    """True if a directory-level value can only weaken the configuration.

    Whether .htaccess applies depends on AllowOverride and on the requested path, which this
    checker does not model. Such values are therefore used to raise risk, never to lower it.
    """
    if s.key == "memory_limit":
        return ini_bytes(s.value) != -1
    if s.key in ("session.upload_progress.enabled", "fatal_error_backtraces"):
        return ini_bool(s.value) is not False
    return False


def is_idle(u: Unit) -> bool:
    return u.running is False and not u.frontends


def set_desc(s: Setting) -> str:
    lock = ", php_admin 잠금" if s.locked else ""
    return f"{s.key}={s.value} ({s.location}{lock})"


def evaluate(units: List[Unit], webscans: Dict[str, WebrootScan], host: Host) -> Tuple[List[Finding], Dict[str, Tuple[str, str]]]:
    findings: List[Finding] = []
    vstatus: Dict[str, Tuple[str, str]] = {}
    for u in units:
        status, vexp = version_status(u, host)
        vstatus[u.id] = (status, vexp)
        comp = f"{u.package or 'php-fpm'} · {u.label}"
        fixed_str = ".".join(map(str, FIXED[u.branch])) if u.branch in FIXED else "없음(EOL)" if u.branch and u.branch < (8, 2) else "-"
        scans = [webscans[r] for fe in u.frontends for r in fe.roots if r in webscans]
        user_level = [s for ws in scans for s in ws.user_ini + ws.ini_set if s.origin != ".htaccess"]
        common_notes = []
        if not u.frontends:
            common_notes.append("이 pool로 요청을 보내는 웹서버 설정을 찾지 못했습니다. 외부 노출 여부는 별도 확인이 필요합니다.")
        if u.running is False:
            common_notes.append("점검 시점에 이 서비스 프로세스가 실행 중이 아니었습니다.")
        if u.incomplete:
            common_notes.append("읽지 못한 설정 파일: " + ", ".join(u.incomplete))
        common_notes.extend(u.notes)

        def add(cve, verdict, conf, condition, rationale, extra_path, notes):
            findings.append(Finding(
                f"F{len(findings) + 1:02d}", cve, u.id, comp, CVSS, fixed_str, verdict, VERDICT_KO[verdict],
                conf, condition, rationale, base_path(u) + extra_path, notes + common_notes))

        if status == "patched":
            for cve in CVES:
                remote_only = (u.version_source or "").startswith("원격")
                add(cve, "patched", "high" if "≥" in vexp and not remote_only else "medium", "패치 적용", vexp, [],
                    ["버전은 원격 응답 헤더 기준입니다. 서버 패키지로 확인하십시오."] if remote_only else [])
            continue
        if is_idle(u):
            for cve in CVES:
                add(cve, "undetermined", "medium", f"SAPI={u.sapi}, 서비스 중지·웹서버 연결 없음",
                    "점검 시점에 요청을 처리하지 않는 설치입니다. 서비스를 시작하면 같은 조건이 적용됩니다.", [], [])
            continue

        conf_floor = "medium" if (not u.frontends or u.incomplete) else "high"

        # CVE-2026-109618: OOM during multipart parsing (DOC:39-45).
        ml = u.settings["memory_limit"]
        overrides = [s for s in user_level if s.key == "memory_limit"]
        notes = []
        if ini_bytes(ml.value) == -1 and (ml.locked or not overrides):
            verdict = "mitigated"
            conf = "high" if ml.locked else "low"
            rationale = f"memory_limit=-1로 OOM 중단 경로가 제거됨({ml.location})."
            if not ml.locked:
                notes.append("php_admin 값이 아니라 앱이 다시 유한값으로 바꿀 수 있습니다(DOC:101).")
            if pending_restart(u, host, ml):
                verdict, conf = "undetermined", "medium"
                notes.append(RESTART_NOTE)
        elif u.sapi == "apache2handler":
            verdict, conf = "reachable", conf_floor
            rationale = "mod_php는 request startup 실패 후에도 cleanup을 수행해 앱 코드 실행 전에 공격이 성립합니다(DOC:43)."
        else:
            verdict, conf = "undetermined", "medium"
            rationale = ("FPM은 startup 실패 시 워커를 종료해 이 경로가 차단되지만, startup 이후 취약할 수 있다는 분석이 있어 "
                         "도달불가로 단정할 수 없습니다(DOC:44).")
        for s in overrides:
            notes.append(f"앱/디렉터리 수준 memory_limit 변경 발견: {set_desc(s)}")
        if verdict == "mitigated" and u.incomplete:
            verdict, conf = "undetermined", "low"
            notes.append("읽지 못한 설정 파일이 완화 설정을 덮어쓸 수 있어 완화로 판정하지 않습니다.")
        add(CVES[0], verdict, conf, f"SAPI={u.sapi}, {set_desc(ml)}", rationale,
            [f"multipart 파싱 중 memory_limit 초과 → 부분 초기화 데이터 정리"], notes)

        # CVE-2026-109619: stale state UAF via session.upload_progress / fatal_error_backtraces (DOC:47-55).
        up = u.settings["session.upload_progress.enabled"]
        notes = []
        for s in user_level:
            if s.key == "session.upload_progress.enabled":
                notes.append(f"{set_desc(s)} — {s.origin}/ini_set은 적용 시점이 늦어 효과가 없습니다(DOC:108).")
        fe_bt = u.settings["fatal_error_backtraces"]
        bt_path = (u.sapi == "apache2handler" and u.branch is not None and u.branch >= (8, 5)
                   and ini_bool(fe_bt.value) is not False)
        if ini_bool(up.value) is False and not bt_path:
            verdict, conf = "mitigated", "high"
            rationale = f"session.upload_progress.enabled=0이 요청 파싱 전 단계에 설정됨({up.location})."
            if up.origin == "nginx":
                conf = "medium"
                notes.append("nginx fastcgi_param PHP_VALUE는 요청 단위로 전달됩니다. pool의 php_admin_value로 옮기는 것을 권장합니다.")
            if pending_restart(u, host, up):
                verdict, conf = "undetermined", "medium"
                notes.append(RESTART_NOTE)
        else:
            verdict, conf = "reachable", conf_floor
            if bt_path:
                rationale = f"mod_php + PHP 8.5 + fatal_error_backtraces 활성({fe_bt.location}) 경로가 성립합니다(DOC:53)."
            else:
                rationale = (f"session.upload_progress가 활성({up.location})이라 session_start() 없이도 세션 라이프사이클 "
                             f"경로가 성립합니다. mod_php·FPM 모두 해당(DOC:54).")
        if u.incomplete and (verdict == "mitigated" or (up.origin == "default" and not bt_path)):
            verdict, conf = "undetermined", "low"
            rationale = "설정 파일 일부를 읽지 못해 실효값을 확정할 수 없습니다."
        add(CVES[1], verdict, conf, f"SAPI={u.sapi}, {set_desc(up)}", rationale,
            ["fatal error로 정리 중단 → 같은 워커의 다음 요청이 stale state 소비"], notes)
    return findings, vstatus


def remediations(units: List[Unit], findings: List[Finding], vstatus, host: Host,
                 webscans: Dict[str, WebrootScan], log_hits: List[LogHit],
                 remote: List[dict]) -> List[Remediation]:
    rems: List[Remediation] = []
    by_key: Dict[Tuple[str, str], Remediation] = {}

    def add(r: Remediation, unit: Optional[str] = None) -> None:
        key = (r.title, r.location, r.fix, r.verify)
        if key in by_key:
            if unit and unit not in by_key[key].units:
                by_key[key].units.append(unit)
            return
        if unit:
            r.units.append(unit)
        by_key[key] = r
        rems.append(r)

    for u in units:
        status, vexp = vstatus[u.id]
        restart = (f"sudo systemctl restart {u.service}" if u.service
                   else "docker restart <컨테이너>   # 컨테이너라면 이미지 재빌드·재배포가 원칙")
        recheck = "sudo python3 php2shell_host.py  # 재점검으로 판정 변화 확인"
        target = (f"{u.pool.file} 의 [{u.pool.name}] 섹션" if u.pool else
                  "Apache 설정(예: /etc/apache2/conf-available/php2shell.conf, a2enconf로 활성화)")
        admin = "php_admin_value[{k}] = {v}" if u.pool else "php_admin_value {k} {v}"

        if is_idle(u):
            pass  # covered by the "unused installation" item below
        elif status == "eol":
            add(Remediation(
                "now", f"PHP {u.branch_str}: 패치가 존재하지 않는 브랜치 — 노출 축소 결정",
                vexp, f"{u.package} {u.package_version or ''}".strip() if u.package else f"PHP {u.version or u.branch_str}",
                u.version_source or u.package or "-",
                "업그레이드 일정과 별개로, 그때까지의 노출을 줄이는 결정이 필요합니다.\n"
                "· 외부 접근 범위 축소(관리 화면·업로드 경로 접근 제한, WAF 적용 여부 확인)\n"
                "· 아래 임시 완화 항목 전부 적용\n"
                "· CISA는 패치할 수 없는 시스템의 오프라인 전환을 권고(DOC:114)",
                "결정 사항과 적용 범위를 기록", "", f"{DOC}:70, :114"), u.id)
        elif status == "backport_only":
            add(Remediation(
                "now", f"PHP {u.branch_str}: 패키지 공급원에 백포트 여부 확인",
                vexp,
                f"{u.package} {u.package_version or ''}".strip() if u.package else f"PHP {u.version or u.branch_str}",
                package_origin(u.package_version or "") if u.package else (u.version_source or "-"),
                "패키지 공급원의 보안 업데이트를 확인하고, 없으면 지원 브랜치로 이전합니다." if u.package else
                "공식 이미지에는 벤더 백포트가 없습니다. 수정이 포함된 지원 브랜치 태그로 베이스 이미지를 올려 재빌드·재배포합니다.",
                f"zcat /usr/share/doc/{u.package}/changelog.Debian.gz | grep -E '{'|'.join(CVES)}'" if u.package else
                "docker exec <컨테이너> php -v",
                "", f"{DOC}:69"), u.id)
        elif status == "vulnerable":
            add(Remediation(
                "now", f"{u.package or 'PHP ' + u.branch_str} 보안 업데이트",
                vexp, u.package_version or u.version or "-", u.version_source or "-",
                f"sudo apt-get install --only-upgrade {u.package} && {restart}" if u.package else
                f"베이스 이미지를 수정 버전 이상의 태그(예: php:{'.'.join(map(str, FIXED[u.branch]))}-…)로 올려 다시 빌드·배포",
                f"dpkg -s {u.package} | grep Version" if u.package else "docker exec <컨테이너> php -v",
                "", f"{DOC}:65-68"), u.id)

        if status == "patched":
            continue
        if is_idle(u):
            add(Remediation(
                "hygiene", f"미사용 PHP {u.branch_str} 설치 정리",
                "실행 중이 아니고 웹서버 연결도 없지만, 시작되면 같은 취약 조건으로 서비스됩니다.",
                f"{u.package or u.label} {u.package_version or ''} (서비스 중지)".strip(),
                u.version_source or u.package or (u.pool.file if u.pool else "-"),
                (f"필요 없으면 제거: sudo apt-get purge {u.package}\n" if u.package else "")
                + (f"유지한다면 자동 시작 해제: sudo systemctl disable --now {u.service}" if u.service else
                   "컨테이너라면 이 PHP를 시작하는 서비스/CMD를 이미지에서 제거하거나 실행하지 않습니다."),
                (f"systemctl is-enabled {u.service}" if u.service else "docker exec <컨테이너> ps -e")
                + (f"; dpkg -l {u.package}" if u.package else "")), u.id)
            continue
        uf = {f.cve: f for f in findings if f.unit == u.id}

        pending = [f for f in uf.values() if RESTART_NOTE in f.notes]
        if pending:
            via_nginx = any(u.settings[k].origin == "nginx" for k in ("memory_limit", "session.upload_progress.enabled"))
            add(Remediation(
                "now", "변경한 완화 설정이 로드됐는지 확인·재시작",
                "완화 설정 파일이 서비스 시작 이후 수정됐습니다. reload로 반영됐는지 파일만으로는 알 수 없습니다(mtime 기준 추정).",
                "\n".join(f.condition for f in pending),
                u.pool.file if u.pool else (u.service or u.version_source or "-"),
                ("sudo nginx -t && sudo systemctl reload nginx\n" if via_nginx else "") + restart,
                recheck, "재시작 중 짧은 요청 실패 가능", f"{DOC}:108"), u.id)

        f19 = uf.get(CVES[1])
        if f19 and f19.verdict == "reachable":
            up = u.settings["session.upload_progress.enabled"]
            if ini_bool(up.value) is not False:
                fix = f"{target}에 추가:\n" + admin.format(k="session.upload_progress.enabled", v="0")
                if up.origin == "php.ini":
                    fix += f"\n(또는 {up.location} 줄을 'session.upload_progress.enabled = Off'로 변경)"
                fix += "\n※ ini_set()·.user.ini로는 효과 없음"
                add(Remediation(
                    "temp", "CVE-2026-109619 임시 완화: session.upload_progress 비활성화",
                    "기본 활성 상태의 upload progress가 stale state 소비 경로를 엽니다.",
                    set_desc(up), up.location if up.origin != "default" else (u.pool.file if u.pool else "php.ini"),
                    fix, f"{restart}\n{recheck}",
                    "세션 기반 업로드 진행률 표시 기능이 동작하지 않습니다.", f"{DOC}:54, :108"), u.id)
        bt = u.settings["fatal_error_backtraces"]
        if f19 and f19.verdict != "mitigated" and u.branch and u.branch >= (8, 5) and ini_bool(bt.value) is not False:
            add(Remediation(
                    "temp", "CVE-2026-109619 임시 완화: fatal_error_backtraces 비활성화(PHP 8.5)",
                    "PHP 8.5 기본값에서 활성이며, mod_php에서는 RCE 경로가 확인됐습니다.", set_desc(bt),
                    bt.location if bt.origin != "default" else target,
                    f"{target}에 추가:\n" + admin.format(k="fatal_error_backtraces", v="0"),
                    f"{restart}\n{recheck}", "", f"{DOC}:53, :109"), u.id)

        f18 = uf.get(CVES[0])
        ml = u.settings["memory_limit"]
        if f18 and f18.verdict != "mitigated" and not (ini_bytes(ml.value) == -1 and ml.locked):
            pm = u.settings["post_max_size"]
            um = u.settings["upload_max_filesize"]
            pm_b, um_b = ini_bytes(pm.value), ini_bytes(um.value)
            body = [fe for fe in u.frontends if fe.kind == "nginx"]
            lines = [
                f"{target}에 추가:",
                admin.format(k="memory_limit", v="-1"),
            ]
            limit = 32 * 1024 ** 2
            if pm_b is None or pm_b <= 0 or pm_b > limit:  # 0 means unlimited
                lines.append(admin.format(k="post_max_size", v="32M") + "   ; 업로드 불필요 시 8M")
                pm_target = limit
            else:
                pm_target = pm_b
            if um_b is None or um_b <= 0 or um_b >= pm_target:
                lines.append(admin.format(k="upload_max_filesize", v=fmt_size(pm_target // 2))
                             + "   ; post_max_size보다 작게")
            lines += [
                "",
                "memory_limit=-1은 요청별 상한을 없애므로 서비스 단위 메모리 상한을 함께 둡니다:",
            ] + ([
                f"sudo systemctl edit {u.service}",
                "  [Service]",
                "  MemoryMax=<서버 메모리에 맞는 값>",
            ] if u.service else [
                "컨테이너 메모리 제한: compose의 mem_limit 또는 docker run --memory",
            ]) + [
                "(RLIMIT_AS/RLIMIT_DATA는 사용하지 않습니다)",
            ]
            current = [set_desc(ml), set_desc(pm), set_desc(um)]
            for fe in body:
                current.append(f"nginx client_max_body_size={fe.body_limit or '1m(기본값)'}"
                               f" ({fe.body_limit_loc or fe.location})")
            add(Remediation(
                "temp", "CVE-2026-109618 임시 완화: memory_limit 잠금 + 요청 크기 제한",
                "multipart 파싱 중 memory_limit 초과로 부분 초기화된 요청 데이터가 정리되며 메모리 손상이 일어납니다."
                + (" mod_php는 앱 코드 실행 전에 성립합니다." if u.sapi == "apache2handler" else ""),
                "\n".join(current), u.pool.file if u.pool else (ml.location if ml.origin != "default" else target),
                "\n".join(lines), f"{restart}\n{recheck}",
                "앱이 multipart를 쓰지 않으면 웹서버 앞단에서 multipart 요청 자체를 차단하는 것이 가장 확실합니다(DOC:105).",
                f"{DOC}:101-105"), u.id)

        for ws in (webscans[r] for fe in u.frontends for r in fe.roots if r in webscans):
            for s in ws.user_ini + ws.ini_set:
                if s.origin == ".htaccess":
                    continue
                if s.key == "session.upload_progress.enabled" and ini_bool(s.value) is False:
                    add(Remediation(
                        "temp", "효과 없는 완화 설정 정리", "이 위치의 설정은 요청 파싱 이후 적용되어 효과가 없습니다.",
                        set_desc(s), s.location, "해당 줄을 제거하고 pool/php.ini 수준 설정으로 옮깁니다.",
                        recheck, "", f"{DOC}:108"), u.id)

        ep = u.settings["expose_php"]
        if ini_bool(ep.value) is not False:
            add(Remediation(
                "hygiene", "PHP 버전 헤더 노출 차단(expose_php)",
                "X-Powered-By로 PHP 버전이 공개되어 공격 대상 선별에 쓰입니다.", set_desc(ep),
                ep.location if ep.origin != "default" else "php.ini",
                f"{ep.location if ep.origin == 'php.ini' else 'php.ini'}: expose_php = Off",
                f"{restart}\ncurl -sI https://<호스트>/ | grep -i x-powered-by   # 출력이 없어야 함"), u.id)

    # TLS chain (nginx ssl_certificate / Apache SSLCertificateFile without chain file).
    for fe in {id(f): f for u in units for f in u.frontends}.values():
        for cert, where in fe.ssl_certs:
            if cert_count(host, cert) == 1 and not fe.chain_file:
                add(Remediation(
                    "hygiene", "TLS 인증서 체인 누락(중간 CA 미포함)",
                    "서버가 leaf 인증서만 보내 Python·curl·일부 모바일 클라이언트에서 검증이 실패합니다. "
                    "브라우저는 AIA로 보완해 정상처럼 보입니다.",
                    f"{cert}: 인증서 1개", where,
                    "leaf 뒤에 중간 CA를 이어 붙인 fullchain 파일로 교체:\n"
                    f"cat <leaf.crt> <intermediate.crt> > <fullchain.crt>\nssl_certificate <fullchain.crt>;",
                    "sudo nginx -t && sudo systemctl reload nginx\n"
                    "openssl s_client -connect <호스트>:443 -servername <호스트> -showcerts </dev/null | grep -c 'BEGIN CERT'  # 2 이상"))

    for r in remote:
        notes = " ".join(r.get("notes") or [])
        if "중간 CA" in notes or "unable to get local issuer" in (r.get("reason") or ""):
            add(Remediation(
                "hygiene", "TLS 인증서 체인 누락(중간 CA 미포함)", "원격 점검에서 인증서 체인 검증이 실패했습니다.",
                r.get("reason", ""), f"원격: {r.get('target')}",
                "웹서버의 인증서 설정을 fullchain(leaf + 중간 CA) 파일로 교체합니다.",
                "openssl s_client -connect <호스트>:443 -servername <호스트> -showcerts </dev/null | grep -c 'BEGIN CERT'  # 2 이상"))

    # Possible compromise: evidence to check, never a verdict.
    if log_hits:
        detail = "\n".join(f"{h.file}: {h.category} {h.count}건" for h in log_hits)
        add(Remediation(
            "check", "침해 징후 확인: 워커 비정상 종료·메모리 한도 초과 로그",
            "공격 시도와 일반 버그 모두 원인이 될 수 있습니다. 발생 시점이 "
            f"{FIRST_SEEN} 이후에 몰리는지, multipart POST 요청과 시각이 겹치는지 확인합니다.",
            detail, "로그", "해당 시각의 access log에서 요청 경로·출발지를 대조합니다.",
            "grep -E 'POST' /var/log/nginx/access.log | awk '{print $4, $1, $7}' | less"))
    recent = [(ws.root, ws) for ws in webscans.values() if ws.recent_total]
    for root, ws in recent:
        add(Remediation(
            "check", f"침해 징후 확인: {FIRST_SEEN} 이후 변경된 .php 파일",
            "배포에 의한 정상 변경일 수 있습니다. 배포 이력과 대조해 설명되지 않는 파일을 확인합니다.",
            f"{ws.recent_total}개" + (" (일부만 표시)" if ws.recent_total > len(ws.recent_php) else ""), root,
            "\n".join(f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(mt))}  {p}" for p, mt in ws.recent_php[:15]),
            f"find {root} -name '*.php' -newermt {FIRST_SEEN} -ls"))
    order = {"now": 0, "temp": 1, "hygiene": 2, "check": 3}
    rems.sort(key=lambda r: order[r.priority])
    return rems


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def build_report(host: Host, args) -> dict:
    procs = scan_procs(host)
    pkgs = dpkg_installed(host)
    fronts = nginx_frontends(host)
    apache = parse_apache(host)
    units = build_units(host, pkgs, procs, fronts, apache)

    remote: List[dict] = []
    for path in args.remote_json or []:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        remote.extend(r for r in (data if isinstance(data, list) else [data]) if isinstance(r, dict))
    for u in units:
        if u.version is None and u.branch:
            # Only borrow a remotely observed version for the vhost it was observed on.
            names = {n.lower() for fe in u.frontends for n in fe.names}
            hit = next((r for r in remote if r.get("detected_version")
                        and branch_of(str(r["detected_version"])) == u.branch
                        and (urlparse(str(r.get("final_url") or r.get("target") or "")).hostname or "") in names),
                       None)
            if hit:
                u.version = hit["detected_version"]
                u.version_source = f"원격 헤더 {hit.get('version_source')} ({hit.get('target')})"

    since = time.mktime(time.strptime(args.since, "%Y-%m-%d"))
    roots = sorted({r for u in units for fe in u.frontends for r in fe.roots} | set(args.webroot or []))
    webscans = {r: scan_webroot(host, r, since) for r in roots if host.isdir(r)}
    for r in args.webroot or []:
        for u in units:
            for fe in u.frontends:
                if r not in fe.roots:
                    fe.roots.append(r)
    log_hits = scan_logs(host)

    # mod_php applies .htaccess php_value/php_flag per directory before the request is parsed,
    # so for mod_php they are part of the effective configuration (approximated as one layer).
    for u in units:
        if u.sapi != "apache2handler":
            continue
        ht = Layer("htaccess", [s for fe in u.frontends for r in fe.roots if r in webscans
                                for s in webscans[r].user_ini if s.origin == ".htaccess" and loosens(s)])
        if ht.entries:
            u.settings, notes = resolve(u.layers + [ht])
            u.notes.extend(n for n in notes if n not in u.notes)

    findings, vstatus = evaluate(units, webscans, host)
    rems = remediations(units, findings, vstatus, host, webscans, log_hits, remote)

    hostname = (host.read_text("/etc/hostname") or "").strip() or (socket.gethostname() if not host.prefix else "fixture")
    counts = {k: sum(1 for f in findings if f.verdict == k) for k in VERDICT_KO}
    return {
        "project": hostname,
        "tool": f"php2shell_host.py v{VERSION}",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "basis": DOC,
        "summary": {
            "units": len(units),
            "findings": len(findings),
            **counts,
            "eol_units": [u.id for u in units if vstatus[u.id][0] == "eol"],
            "compromise_checks": sum(1 for r in rems if r.priority == "check"),
        },
        "units": [{
            "id": u.id, "label": u.label, "sapi": u.sapi, "branch": u.branch_str,
            "package": u.package, "package_version": u.package_version,
            "version": u.version, "version_source": u.version_source,
            "version_status": vstatus[u.id][0], "version_detail": vstatus[u.id][1],
            "pool": u.pool.name if u.pool else None, "listen": u.pool.listen if u.pool else None,
            "running": u.running,
            "started_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(u.started)) if u.started else None,
            "frontends": [{"kind": f.kind, "names": f.names, "location": f.location, "route": f.route,
                           "roots": f.roots} for f in u.frontends],
            "settings": {k: asdict(v) for k, v in u.settings.items()},
            "notes": u.notes,
        } for u in units],
        "items": [asdict(f) for f in findings],
        "remediation": [asdict(r) for r in rems],
        "log_hits": [asdict(h) for h in log_hits],
        "remote": remote,
        "transparency": {
            "files_read": host.files_read,
            "files_denied": host.denied,
            "commands_executed": 0,
            "network_requests": 0,
            "writes": [args.out],
            "root": host.prefix or "/",
            "limits": {"conf_bytes": MAX_CONF_BYTES, "log_tail_bytes": MAX_LOG_BYTES,
                       "php_file_bytes": MAX_PHP_BYTES, "walk_files": MAX_WALK_FILES},
            "webroot_scans": [{"root": w.root, "files_seen": w.files_seen, "truncated": w.truncated}
                              for w in webscans.values()],
        },
    }


def md_escape(s) -> str:
    """Plain text inside Markdown (table cells, list items). Config values and log lines are untrusted."""
    text = str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return text.replace("`", "\\`").replace("|", "\\|").replace("\n", "<br>")


def _longest_backticks(text: str) -> int:
    return max((len(m) for m in re.findall(r"`+", text)), default=0)


def md_code(s) -> str:
    """Inline code span that the content cannot break out of."""
    text = str(s).replace("\n", " ")
    delim = "`" * (_longest_backticks(text) + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{delim}{pad}{text}{pad}{delim}"


def md_block(text, lang: str = "") -> List[str]:
    fence = "`" * max(3, _longest_backticks(str(text)) + 1)
    return [fence + lang, str(text), fence]


# Closing guidance for administrators running an old PHP in production. Static text; every
# claim points at the basis document so the report never asserts more than the document does.
OPS_GUIDE = [
    ("1. 오늘: 서비스를 멈추지 않고 할 수 있는 일", [
        "인터넷에 공개된 PHP 경로와 업로드·관리 화면을 파악하고, 불필요한 공개부터 닫습니다.",
        "§조치 사항의 임시 완화를 적용하고 모든 워커를 재시작합니다. 설정만으로는 완전히 완화되지 않습니다(DOC:96, :108).",
        "웹서버·프록시 앞단에서 요청 크기·multipart 파트 수를 제한하고, multipart를 쓰지 않는 앱은 차단합니다(DOC:103, :105). "
        "WAF는 그 경로를 지나는 트래픽에만 효과가 있는 임시방편입니다(DOC:115).",
        f"침해 조사 범위는 공개일이 아니라 {FIRST_SEEN}부터 잡습니다(DOC:125). 로그가 없다고 안전한 것은 아닙니다(DOC:126).",
    ]),
    ("2. 이번 주: 보안 수정이 들어간 패키지 확보", [
        "배포판·LTS 벤더 패키지의 보안 업데이트를 확인합니다. 배포판 패키지는 changelog로 백포트 여부를 확인합니다(DOC:69, :72, :172).",
        "확장 지원 서비스(예: 배포판의 유료 확장 보안 지원, 상용 PHP 장기 지원)로 수정판을 받을 수 있는지 확인합니다. 제공 여부는 공급자에게 직접 확인해야 합니다.",
        "PHP 7.3 이하는 PHP 측 패치와 소스 백포트가 없습니다(DOC:70). 이 단계를 건너뛰고 3·4단계로 갑니다.",
    ]),
    ("3. 업그레이드 경로: 중단 없이 옮기기", [
        "목표는 보안 지원 중인 브랜치입니다. 8.2는 2026-12-31에 지원이 끝나므로 8.3 이상을 권장합니다(DOC:161).",
        "호환성은 정적 분석(예: PHP_CodeSniffer의 PHPCompatibility 규칙)과 자동 변환 도구(예: Rector)로 먼저 확인하고, "
        "사용 중인 확장 모듈·프레임워크·CMS가 목표 버전을 지원하는지 확인합니다.",
        "새 버전을 별도 FPM pool이나 컨테이너로 나란히 띄워 스테이징 → 일부 트래픽 → 전체 전환 순으로 옮기고, 이전 버전으로 되돌릴 경로를 남겨 둡니다.",
    ]),
    ("4. 당장 업그레이드할 수 없을 때", [
        "인터넷 직접 노출을 없애고, 접근 통제된 내부망·VPN 뒤로 옮기거나 꼭 필요한 기능만 리버스 프록시로 공개합니다.",
        "CISA는 패치할 수 없거나 8.1 이하인 시스템의 오프라인 전환을 권고했습니다(DOC:114).",
        "그래도 운영을 계속한다면 위험 수용을 문서로 남깁니다: 승인 책임자, 적용한 보완 통제, 재검토 기한.",
    ]),
    ("5. 다른 조직의 서버에서 발견했을 때", [
        "허가 없이 직접 점검·검증하지 않습니다. 운영 주체나 공식 신고 채널(국내는 KISA 보호나라·KrCERT/CC)로 알립니다.",
        "조치가 끝나기 전에는 취약 사실과 대상을 공개하지 않습니다.",
    ]),
]


def render_md(rep: dict) -> str:
    s = rep["summary"]
    out = [f"# PHP2Shell 노출 점검 보고서", "",
           f"**호스트:** {md_escape(rep['project'])}  ",
           f"**점검 시각:** {rep['generated_at']}  ",
           f"**점검 도구:** {rep['tool']} (비파괴: 실행 명령 0건, 네트워크 요청 0건)  ",
           f"**판정 근거:** {rep['basis']} §2", "",
           "## 1. 요약 (Executive Summary)", "",
           f"서빙 경로 **{s['units']}개**에서 PHP2Shell(CVE-2026-109618 / CVE-2026-109619) {s['findings']}건을 판정한 결과 "
           f"**도달가능 {s['reachable']}건**, 완화됨(임시) {s['mitigated']}건, 판정보류 {s['undetermined']}건, "
           f"패치됨 {s['patched']}건입니다.", ""]
    if not s["units"]:
        out += ["> ⚠️ **PHP 서빙 경로를 찾지 못했습니다.** 지원하지 않는 배치이거나 설정을 읽지 못했을 수 있습니다. "
                "'도달가능 0건'은 안전을 뜻하지 않습니다.", ""]
    if s["eol_units"]:
        out += [f"> ⚠️ **패치가 존재하지 않는 PHP 브랜치가 서비스 중입니다** ({', '.join(s['eol_units'])}). "
                "업그레이드 외에 수정 수단이 없으므로, 그때까지의 노출 축소를 결정해야 합니다.", ""]
    out += ["> ℹ️ 설정 변경은 **임시 완화**입니다. PHP는 설정만으로 완전히 완화되지 않는다고 밝혔습니다"
            f"({DOC}:96). '완화됨(임시)'은 '안전'이 아닙니다.", ""]
    if s["compromise_checks"]:
        out += [f"> 🔎 침해 징후 확인 항목 {s['compromise_checks']}건이 있습니다(§6). 판정이 아니라 확인이 필요한 근거입니다.", ""]

    out += ["## 2. 점검 대상 (서빙 경로)", "",
            "| ID | 대상 | 패키지 버전 | 버전 판정 | 실행 | 웹서버 |", "|---|---|---|---|---|---|"]
    for u in rep["units"]:
        fe = "<br>".join(md_escape(f"{f['kind']} {' '.join(f['names'][:3])}") for f in u["frontends"]) or "미확인"
        run = {True: f"실행 중 (시작 {u['started_at'] or '?'})", False: "중지", None: "확인 불가"}[u["running"]]
        out.append(f"| {u['id']} | {md_escape(u['label'])} | {md_escape(u['package_version'] or u['version'] or '-')} | "
                   f"{md_escape(u['version_detail'])} | {run} | {fe} |")
    out.append("")

    out += ["## 3. CVE별 판정", "",
            "| ID | CVE | 대상 | 심각도 | 판정 | 신뢰도 | 수정버전 | 근거 |", "|---|---|---|---|---|---|---|---|"]
    icon = {"reachable": "🔴", "mitigated": "🟡", "undetermined": "⚪", "patched": "🟢"}
    for f in rep["items"]:
        out.append(f"| {f['id']} | {f['cve']} | {f['unit']} | {f['severity']} | {icon[f['verdict']]} {f['verdict_ko']} | "
                   f"{f['confidence']} | {f['fixed_version']} | {md_escape(f['rationale'])} |")
    out.append("")

    out += ["## 4. 판정 근거 (서빙 경로)", ""]
    for f in rep["items"]:
        out += [f"### {f['id']} {f['cve']} — {f['verdict_ko']} ({f['unit']})", "",
                f"**조건:** {md_code(f['condition'])}", "", "```mermaid", "flowchart LR"]
        for i, node in enumerate(f["evidence_path"]):
            label = node.replace('"', "'").replace("`", "'").replace("<", "&lt;").replace(">", "&gt;")
            out.append(f'  n{i}["{label}"]')
        out += [f"  n{i} --> n{i + 1}" for i in range(len(f["evidence_path"]) - 1)]
        out += ["```", ""]
        out += [f"- {md_escape(n)}" for n in f["notes"]]
        out.append("")

    out += ["## 5. 조치 사항 (Remediation)", ""]
    for i, r in enumerate([r for r in rep["remediation"] if r["priority"] != "check"], 1):
        out += [f"### 5.{i} [{PRIO_KO[r['priority']]}] {r['title']}", "",
                f"- **문제:** {md_escape(r['problem'])}",
                f"- **현재:** {md_escape(r['current'])}",
                f"- **위치:** {md_code(r['location'])}" + (f" (대상: {', '.join(r['units'])})" if r["units"] else ""),
                "- **조치:**", ""] + md_block(r["fix"]) + ["",
                "- **확인:**", ""] + md_block(r["verify"], "bash") + [""]
        if r["impact"]:
            out.append(f"- **영향:** {r['impact']}")
        if r["refs"]:
            out.append(f"- **근거:** {r['refs']}")
        out.append("")

    out += ["## 6. 침해 징후 점검 (확인 필요)", ""]
    checks = [r for r in rep["remediation"] if r["priority"] == "check"]
    if not checks:
        out += ["점검한 로그와 웹루트에서 확인이 필요한 항목을 찾지 못했습니다. 공개된 IOC는 아직 없으므로(DOC:120) "
                "이 결과가 침해되지 않았다는 증명은 아닙니다.", ""]
    for r in checks:
        out += [f"### {md_escape(r['title'])}", "", md_escape(r["problem"]), ""] \
            + md_block(f"{r['current']}\n\n{r['fix']}") + ["", f"확인: {md_code(r['verify'])}", ""]
    for h in rep["log_hits"]:
        out += [f"- {md_code(h['file'])} {h['category']} {h['count']}건 — 최근 예: {md_code(h['samples'][-1])}"]
    out.append("")

    t = rep["transparency"]
    out += ["## 7. 투명성 부록", "",
            f"- **실행한 명령:** {t['commands_executed']}건 · **네트워크 요청:** {t['network_requests']}건 · "
            f"**쓰기:** 보고서 디렉터리({md_code(t['writes'][0])})만",
            f"- **읽은 파일:** {len(t['files_read'])}개 (전체 목록은 report.json `transparency.files_read`)",
            f"- **권한 부족으로 읽지 못한 파일:** {len(t['files_denied'])}개" +
            (" — " + ", ".join(md_code(p) for p in t["files_denied"][:20]) if t["files_denied"] else ""),
            f"- **상한:** 설정 {t['limits']['conf_bytes'] // 1024 // 1024}MiB, 로그 끝 {t['limits']['log_tail_bytes'] // 1024 // 1024}MiB, "
            f"웹루트 파일 {t['limits']['walk_files']}개",
            "", "**한계:**",
            "- 설정 파일을 읽어 실효값을 계산합니다. 실행 중인 프로세스의 실제 값과 다를 수 있으며, 재시작 반영 여부는 파일 수정 시각으로 추정합니다.",
            "- Apache의 php_value/php_admin_value는 VirtualHost·Directory 구분 없이 전역으로 취급합니다.",
            "- RHEL 계열은 패키지 버전을 확인하지 못합니다(rpm DB 미해석). php-cgi, LiteSpeed, FrankenPHP는 점검하지 않습니다.",
            "- 메모리 레이아웃·워커 재사용 등 익스플로잇 성공 조건(AC:H/AT:P)은 판정하지 않습니다.", ""]
    out += ["## 8. 운영 중인 구버전 PHP 서버 대응 안내", "",
            "업그레이드가 답이라는 것은 대개 이미 알고 있습니다. 문제는 운영 중인 서버를 그때까지 어떻게 다루느냐입니다.", ""]
    for title, items in OPS_GUIDE:
        out += [f"**{title}**", ""] + [f"- {i}" for i in items] + [""]
    out += [f"근거 표기의 DOC는 {DOC}입니다.", ""]
    return "\n".join(out)


CSS = """
:root{--paper:#FCFCFB;--desk:#E7E6E1;--ink:#15181B;--ink-2:#3B4147;--ink-3:#6C7278;--ink-4:#9AA0A4;
--line:#E4E3DD;--line-2:#D2D1CB;--line-strong:#B9B8B1;--teal:#23736F;--teal-deep:#1A5B58;--teal-tint:#EAF2F1;
--teal-line:#BFD8D5;--amber:#B6781C;--amber-strong:#9A6212;--amber-tint:#FBF1DF;--amber-line:#EAD2A0;
--sans:"Pretendard","Apple SD Gothic Neo","Noto Sans CJK KR","Malgun Gothic",-apple-system,system-ui,sans-serif;
--mono:"IBM Plex Mono",ui-monospace,"Cascadia Mono",Consolas,Menlo,monospace;}
*{box-sizing:border-box}html,body{margin:0;padding:0}
body{background:var(--desk);font-family:var(--sans);color:var(--ink);line-height:1.5;padding:40px 16px 64px;-webkit-font-smoothing:antialiased}
.page{width:210mm;min-height:297mm;background:var(--paper);margin:0 auto 30px;box-shadow:0 2px 18px rgba(20,24,28,.10);border-radius:2px;display:flex;flex-direction:column}
.pad{padding:22mm 20mm 0}.flow{flex:1}
.rhead{display:flex;justify-content:space-between;padding:14mm 20mm 0;color:var(--ink-3);font-size:9.5px;letter-spacing:.14em;text-transform:uppercase;font-weight:600}
.rhead .wm{color:var(--ink)}.rhead .wm b{color:var(--teal)}
.rfoot{margin-top:auto;display:flex;justify-content:space-between;padding:0 20mm 12mm;color:var(--ink-4);font-size:9px;letter-spacing:.1em}
.rfoot .conf{letter-spacing:.22em;text-transform:uppercase;color:var(--ink-3);font-weight:600}.rfoot .pg{font-family:var(--mono);color:var(--ink-2)}
.footline{height:1px;background:var(--line);margin:24px 20mm 6mm}
.eyebrow{font-size:10.5px;letter-spacing:.22em;text-transform:uppercase;font-weight:700;color:var(--teal);margin:0 0 10px}
.sec-no{font-family:var(--mono)}h1.sec{font-size:25px;font-weight:700;letter-spacing:-.015em;margin:0 0 4px}
.sec-sub{font-size:12.5px;color:var(--ink-3);margin:0 0 22px}.sec-rule{height:2px;background:var(--ink);width:48px;margin:0 0 24px}
h2{font-size:15px;margin:30px 0 12px}p{font-size:12.5px;color:var(--ink-2);margin:0 0 12px;line-height:1.62}
.mono{font-family:var(--mono)}
.cover-top{padding:24mm 22mm 0}.cover-wm{font-size:15px;font-weight:800;letter-spacing:.42em;text-transform:uppercase;display:flex;align-items:center;gap:11px}
.cover-wm .mark{width:15px;height:15px;border:2.5px solid var(--ink);position:relative;border-radius:2px}
.cover-wm .mark::after{content:"";position:absolute;inset:3px;background:var(--teal)}.cover-wm .gd{color:var(--teal)}
.cover-mid{padding:30mm 22mm 0}.cover-cat{font-size:11px;letter-spacing:.24em;text-transform:uppercase;font-weight:700;color:var(--teal);margin-bottom:16px}
.cover-title{font-size:44px;font-weight:800;letter-spacing:-.03em;line-height:1.08;margin:0}
.cover-desc{margin-top:20px;max-width:130mm;font-size:13px;color:var(--ink-2);line-height:1.68}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:4px 0 26px}
.cover .kpis{margin:26px 22mm 0}
.kpi{border:1px solid var(--line-2);border-radius:5px;padding:16px;background:#fff}
.kpi .n{font-size:32px;font-weight:800;line-height:1;font-variant-numeric:tabular-nums}.kpi .l{font-size:11px;color:var(--ink-3);margin-top:8px;font-weight:600}
.kpi.alert{border-color:var(--amber-line);background:var(--amber-tint)}.kpi.alert .n,.kpi.alert .l{color:var(--amber-strong)}
.kpi.teal{border-color:var(--teal-line);background:var(--teal-tint)}.kpi.teal .n,.kpi.teal .l{color:var(--teal-deep)}
.cover-meta{margin:auto 22mm 22mm;padding-top:24px}.cover-meta-grid{display:grid;grid-template-columns:1fr 1fr;gap:0 40px;border-top:1px solid var(--ink);padding-top:18px}
.cmeta{padding:9px 0;border-bottom:1px solid var(--line)}.cmeta .k{font-size:9.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--ink-3);font-weight:600;margin-bottom:4px}
.cmeta .v{font-size:12.5px}
.callout{border:1px solid var(--amber-line);background:var(--amber-tint);border-radius:5px;padding:16px 18px;display:flex;gap:14px;margin:0 0 16px}
.callout .ic{width:26px;height:26px;border-radius:50%;background:var(--amber);color:#fff;flex:none;display:flex;align-items:center;justify-content:center;font-weight:800}
.callout .ct{font-size:12.5px;color:var(--amber-strong);line-height:1.6}
.callout.teal{border-color:var(--teal-line);background:var(--teal-tint)}.callout.teal .ic{background:var(--teal)}.callout.teal .ct{color:var(--teal-deep)}
.note{border-left:3px solid var(--teal);background:var(--teal-tint);padding:12px 16px;font-size:12px;color:var(--ink-2);margin:0 0 14px}
.ftable{width:100%;border-collapse:collapse;font-size:11px}
.ftable th{text-align:left;font-size:9.5px;letter-spacing:.08em;text-transform:uppercase;color:var(--ink-3);padding:0 8px 9px;border-bottom:2px solid var(--ink)}
.ftable td{padding:10px 8px;border-bottom:1px solid var(--line);vertical-align:top;line-height:1.5}
.ftable tr.reach td{background:var(--amber-tint)}.ftable .c-cve{font-family:var(--mono);white-space:nowrap}
.ftable .c-sm{font-size:10px;color:var(--ink-3)}
.badge{display:inline-block;font-size:9.5px;font-weight:700;padding:3px 8px;border-radius:3px;white-space:nowrap}
.v-reachable{background:var(--amber);color:#fff}.v-mitigated{background:var(--teal-tint);color:var(--teal-deep);border:1px solid var(--teal-line)}
.v-undetermined{background:#fff;color:var(--ink-3);border:1px solid var(--line-2)}.v-patched{background:#fff;color:var(--teal);border:1px solid var(--teal-line)}
.pipeline{display:flex;flex-wrap:wrap;gap:6px 18px;margin:8px 0 10px}
.pstep{position:relative;border:1px solid var(--line-2);border-radius:5px;background:#fff;padding:8px 10px;font-family:var(--mono);font-size:10px;color:var(--ink-2);max-width:100%;word-break:break-all}
.pstep:not(:last-child)::after{content:"\\2192";position:absolute;right:-14px;top:50%;transform:translateY(-50%);color:var(--ink-4)}
.pstep.sink{border-color:var(--amber-line);background:var(--amber-tint);color:var(--amber-strong)}
.card{border:1px solid var(--line-2);border-radius:6px;margin:0 0 16px;break-inside:avoid;overflow:hidden}
.card .top{padding:12px 16px;border-bottom:1px solid var(--line);display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.card.reach{border-color:var(--amber-line)}.card.reach .top{background:var(--amber-tint)}
.card .body{padding:12px 16px}.card .t{font-weight:700;font-size:13px}
.card ul{margin:6px 0 0;padding-left:18px;font-size:11.5px;color:var(--ink-2)}
.kv{display:grid;grid-template-columns:72px 1fr;gap:6px 12px;font-size:11.5px;margin:0}
.kv dt{color:var(--ink-3);font-weight:700}.kv dd{margin:0;color:var(--ink-2)}
pre{font-family:var(--mono);font-size:10.5px;background:#F4F3EE;border:1px solid var(--line);border-radius:4px;padding:10px 12px;white-space:pre-wrap;word-break:break-all;margin:0}
.prio{display:inline-block;font-size:9px;font-weight:700;letter-spacing:.1em;padding:2px 7px;border-radius:3px}
.p-now{background:var(--amber);color:#fff}.p-temp{background:var(--amber-tint);color:var(--amber-strong);border:1px solid var(--amber-line)}
.p-hygiene{background:var(--teal-tint);color:var(--teal-deep);border:1px solid var(--teal-line)}.p-check{background:#fff;color:var(--ink-2);border:1px solid var(--line-strong)}
.trans{width:100%;border-collapse:collapse}.trans td{padding:12px 0;border-bottom:1px solid var(--line);vertical-align:top;font-size:12px;color:var(--ink-2)}
.trans .tk{width:170px;font-weight:700;color:var(--ink)}
.guide{margin:0 0 6px;padding-left:18px;font-size:12px;color:var(--ink-2);line-height:1.62}.guide li{margin:0 0 6px}
.endmark{margin-top:28px;padding-top:18px;border-top:2px solid var(--ink);display:flex;justify-content:space-between;font-size:10px;color:var(--ink-3)}
@media print{@page{size:A4;margin:0}html,body{background:#fff;padding:0}.page{margin:0;box-shadow:none;break-after:page}
.page:last-child{break-after:auto}*{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
@media screen and (max-width:840px){.page{width:100%;min-height:0}.kpis{grid-template-columns:repeat(2,1fr)}.cover-title{font-size:32px}}
"""


def e(s) -> str:
    return html.escape(str(s if s is not None else ""))


def render_html(rep: dict) -> str:
    s = rep["summary"]
    host = e(rep["project"])
    pages: List[str] = []

    def page(no: str, eyebrow: str, title: str, sub: str, body: str) -> None:
        pages.append(
            f'<section class="page"><div class="rhead"><span class="wm">PHP2SHELL <b>CHECK</b></span>'
            f'<span>{e(no)} {e(title)}</span></div><div class="pad flow">'
            f'<p class="eyebrow"><span class="sec-no">{e(no)}</span> &nbsp;{e(eyebrow)}</p>'
            f'<h1 class="sec">{e(title)}</h1><p class="sec-sub">{e(sub)}</p><div class="sec-rule"></div>{body}</div>'
            f'<div class="footline"></div><div class="rfoot"><span>PHP2Shell 노출 점검 보고서 · {host}</span>'
            f'<span class="conf">Confidential</span><span class="pg">{len(pages) + 2:02d}</span></div></section>')

    kpis = (f'<div class="kpis"><div class="kpi"><div class="n">{s["units"]}</div><div class="l">서빙 경로</div></div>'
            f'<div class="kpi alert"><div class="n">{s["reachable"]}</div><div class="l">도달가능</div></div>'
            f'<div class="kpi teal"><div class="n">{s["mitigated"]}</div><div class="l">완화됨(임시)</div></div>'
            f'<div class="kpi"><div class="n">{s["undetermined"] + s["patched"]}</div>'
            f'<div class="l">판정보류 {s["undetermined"]} · 패치됨 {s["patched"]}</div></div></div>')
    cover = (
        '<section class="page cover"><div class="cover-top"><div class="cover-wm"><span class="mark"></span>'
        'PHP2SHELL <span class="gd">CHECK</span></div></div><div class="cover-mid">'
        '<div class="cover-cat">Exposure Assessment · CVE-2026-109618 / 109619</div>'
        '<h1 class="cover-title">PHP2Shell<br>노출 점검 보고서</h1>'
        f'<p class="cover-desc">{host} 서버의 실제 서빙 경로(웹서버 → SAPI/FPM pool → PHP 빌드)와 실효 설정을 읽어 '
        '두 취약점의 성립 조건을 판정하고, 관리자가 적용할 조치를 파일·줄 단위로 제시합니다. 점검은 비파괴로 수행됐습니다.</p></div>'
        f'{kpis}<div class="cover-meta"><div class="cover-meta-grid">'
        f'<div class="cmeta"><div class="k">호스트</div><div class="v">{host}</div></div>'
        f'<div class="cmeta"><div class="k">점검 시각</div><div class="v mono">{e(rep["generated_at"])}</div></div>'
        f'<div class="cmeta"><div class="k">점검 도구</div><div class="v">{e(rep["tool"])}</div></div>'
        f'<div class="cmeta"><div class="k">판정 근거</div><div class="v">{e(rep["basis"])} §2</div></div>'
        '</div></div></section>')

    # 01 summary
    body = kpis
    if not s["units"]:
        body += ('<div class="callout"><div class="ic">!</div><div class="ct"><b>PHP 서빙 경로를 찾지 못했습니다.</b> '
                 '지원하지 않는 배치이거나 설정을 읽지 못했을 수 있습니다. ‘도달가능 0건’은 안전을 뜻하지 않습니다.</div></div>')
    if s["eol_units"]:
        body += ('<div class="callout"><div class="ic">!</div><div class="ct"><b>패치가 존재하지 않는 PHP 브랜치가 서비스 중입니다</b> '
                 f'({e(", ".join(s["eol_units"]))}). 업그레이드 외에 수정 수단이 없으므로 그때까지의 노출 축소를 결정해야 합니다.</div></div>')
    body += ('<div class="callout teal"><div class="ic">i</div><div class="ct">설정 변경은 <b>임시 완화</b>입니다. PHP는 설정만으로 '
             f'완전히 완화되지 않는다고 밝혔습니다({e(DOC)}:96). ‘완화됨(임시)’은 ‘안전’이 아닙니다.</div></div>')
    if s["compromise_checks"]:
        body += (f'<div class="note">침해 징후 확인 항목 <b>{s["compromise_checks"]}건</b>이 있습니다(06). '
                 '판정이 아니라 확인이 필요한 근거입니다.</div>')
    body += ('<h2>판정 기준</h2><table class="trans">'
             '<tr><td class="tk"><span class="badge v-reachable">도달가능</span></td><td>이 서버의 SAPI·실효 설정에서 문서가 확인한 공격 경로의 전제조건이 성립합니다.</td></tr>'
             '<tr><td class="tk"><span class="badge v-mitigated">완화됨(임시)</span></td><td>문서의 임시 완화 설정이 요청 파싱 전 단계에 적용돼 있습니다. 업그레이드 전까지의 조치입니다.</td></tr>'
             '<tr><td class="tk"><span class="badge v-undetermined">판정보류</span></td><td>근거가 부족하거나 설정을 읽지 못해 단정하지 않습니다. 도달불가가 아닙니다.</td></tr>'
             '<tr><td class="tk"><span class="badge v-patched">패치됨</span></td><td>수정 버전 이상이거나 패키지 changelog에 백포트 기록이 있습니다.</td></tr></table>')
    page("01", "Executive Summary", "요약", f"서빙 경로 {s['units']}개 · 판정 {s['findings']}건", body)

    # 02 scope
    rows = ""
    for u in rep["units"]:
        fe = "<br>".join(e(f"{f['kind']} {' '.join(f['names'][:3])}") for f in u["frontends"]) or "미확인"
        run = {True: f"실행 중<br><span class='c-sm'>{e(u['started_at'] or '')}</span>", False: "중지", None: "확인 불가"}[u["running"]]
        rows += (f'<tr><td class="c-cve">{e(u["id"])}</td><td>{e(u["label"])}<br><span class="c-sm">{e(u["package_version"] or u["version"] or "-")}</span></td>'
                 f'<td>{e(u["version_detail"])}</td><td>{run}</td><td class="c-sm">{fe}</td></tr>')
    body = ('<table class="ftable"><thead><tr><th>ID</th><th>대상</th><th>버전 판정</th><th>실행</th><th>웹서버</th></tr></thead>'
            f'<tbody>{rows}</tbody></table>')
    page("02", "Scope", "점검 대상", "웹서버 → SAPI/FPM pool → PHP 빌드 단위로 판정합니다", body)

    # 03 findings
    rows = ""
    for f in rep["items"]:
        rows += (f'<tr class="{"reach" if f["verdict"] == "reachable" else ""}"><td class="c-cve">{e(f["cve"])}</td>'
                 f'<td>{e(f["unit"])}</td><td><span class="badge v-{e(f["verdict"])}">{e(f["verdict_ko"])}</span></td>'
                 f'<td class="c-sm">{e(f["confidence"])}</td><td class="c-sm">{e(f["fixed_version"])}</td>'
                 f'<td>{e(f["rationale"])}</td></tr>')
    body = ('<table class="ftable"><thead><tr><th>CVE</th><th>대상</th><th>판정</th><th>신뢰도</th><th>수정버전</th><th>근거</th></tr></thead>'
            f'<tbody>{rows}</tbody></table><h2>판정 근거 (서빙 경로)</h2>')
    for f in rep["items"]:
        steps = "".join(f'<div class="pstep{" sink" if i == len(f["evidence_path"]) - 1 else ""}">{e(n)}</div>'
                        for i, n in enumerate(f["evidence_path"]))
        notes = "".join(f"<li>{e(n)}</li>" for n in f["notes"])
        body += (f'<div class="card {"reach" if f["verdict"] == "reachable" else ""}"><div class="top">'
                 f'<span class="c-cve mono">{e(f["id"])} {e(f["cve"])}</span>'
                 f'<span class="badge v-{e(f["verdict"])}">{e(f["verdict_ko"])}</span><span class="c-sm">{e(f["unit"])}</span></div>'
                 f'<div class="body"><div class="pipeline">{steps}</div>'
                 f'<p style="margin:0" class="mono c-sm">{e(f["condition"])}</p>{f"<ul>{notes}</ul>" if notes else ""}</div></div>')
    page("03", "Findings", "CVE별 판정", f"{CVSS} · 두 CVE × 서빙 경로", body)

    # 04 remediation
    body = ""
    for r in (r for r in rep["remediation"] if r["priority"] != "check"):
        units = f' · 대상 {e(", ".join(r["units"]))}' if r["units"] else ""
        body += (f'<div class="card"><div class="top"><span class="prio p-{e(r["priority"])}">{e(PRIO_KO[r["priority"]])}</span>'
                 f'<span class="t">{e(r["title"])}</span></div><div class="body"><dl class="kv">'
                 f'<dt>문제</dt><dd>{e(r["problem"])}</dd>'
                 f'<dt>현재</dt><dd class="mono">{e(r["current"]).replace(chr(10), "<br>")}</dd>'
                 f'<dt>위치</dt><dd class="mono">{e(r["location"])}{units}</dd>'
                 f'<dt>조치</dt><dd><pre>{e(r["fix"])}</pre></dd>'
                 f'<dt>확인</dt><dd><pre>{e(r["verify"])}</pre></dd>'
                 + (f'<dt>영향</dt><dd>{e(r["impact"])}</dd>' if r["impact"] else "")
                 + (f'<dt>근거</dt><dd class="c-sm">{e(r["refs"])}</dd>' if r["refs"] else "")
                 + '</dl></div></div>')
    page("04", "Remediation", "조치 사항", "우선순위 순 · 파일·줄 단위", body or "<p>조치할 항목이 없습니다.</p>")

    # 05 compromise + appendix
    checks = [r for r in rep["remediation"] if r["priority"] == "check"]
    body = ""
    if not checks:
        body += ('<p>점검한 로그와 웹루트에서 확인이 필요한 항목을 찾지 못했습니다. 공개된 IOC는 아직 없으므로'
                 f'({e(DOC)}:120) 이 결과가 침해되지 않았다는 증명은 아닙니다.</p>')
    for r in checks:
        body += (f'<div class="card"><div class="top"><span class="prio p-check">확인 필요</span><span class="t">{e(r["title"])}</span></div>'
                 f'<div class="body"><p>{e(r["problem"])}</p><pre>{e(r["current"])}\n\n{e(r["fix"])}</pre>'
                 f'<p class="mono c-sm" style="margin-top:8px">{e(r["verify"])}</p></div></div>')
    for h in rep["log_hits"]:
        body += f'<div class="note"><span class="mono">{e(h["file"])}</span> · {e(h["category"])} {h["count"]}건<pre>{e(chr(10).join(h["samples"]))}</pre></div>'
    t = rep["transparency"]
    denied = ", ".join(t["files_denied"][:20])
    body += ('<h2>투명성 부록</h2><table class="trans">'
             f'<tr><td class="tk">비파괴</td><td>실행한 명령 {t["commands_executed"]}건 · 네트워크 요청 {t["network_requests"]}건 · '
             f'쓰기는 보고서 디렉터리(<span class="mono">{e(t["writes"][0])}</span>)만</td></tr>'
             f'<tr><td class="tk">읽은 파일</td><td>{len(t["files_read"])}개 (전체 목록은 report.json)</td></tr>'
             f'<tr><td class="tk">읽지 못한 파일</td><td class="mono">{len(t["files_denied"])}개 {e(denied)}</td></tr>'
             '<tr><td class="tk">한계</td><td>설정 파일 기준 실효값이며 재시작 반영은 파일 수정 시각으로 추정합니다. Apache php_* 지시자는 전역으로 취급합니다. '
             'RHEL 계열 패키지 버전, php-cgi·LiteSpeed·FrankenPHP, 익스플로잇 성공 조건(AC:H/AT:P)은 판정하지 않습니다.</td></tr></table>'
             f'<div class="endmark"><span>PHP2SHELL CHECK</span><span>{e(rep["generated_at"])}</span></div>')
    page("05", "Compromise & Appendix", "침해 징후 · 부록", "판정이 아닌 확인 항목 · 점검 방식 공개", body)

    # 06 operating guidance
    body = ('<p>업그레이드가 답이라는 것은 대개 이미 알고 있습니다. 문제는 운영 중인 서버를 그때까지 어떻게 다루느냐입니다.</p>')
    for title, items in OPS_GUIDE:
        body += f'<h2>{e(title)}</h2><ul class="guide">' + "".join(f"<li>{e(i)}</li>" for i in items) + "</ul>"
    body += f'<div class="note">근거 표기의 DOC는 {e(DOC)}입니다.</div>'
    body += f'<div class="endmark"><span>PHP2SHELL CHECK</span><span>{e(rep["generated_at"])}</span></div>'
    page("06", "Operating Guidance", "운영 중인 구버전 서버 대응", "오늘 · 이번 주 · 업그레이드 경로 · 불가능할 때", body)

    return ('<!doctype html><html lang="ko"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            f'<title>PHP2Shell 노출 점검 보고서 — {host}</title><style>{CSS}</style></head><body>'
            + cover + "".join(pages) + "</body></html>")


def main() -> int:
    parser = argparse.ArgumentParser(description="PHP2Shell 비파괴 내부 점검기 (서버에서 실행)")
    parser.add_argument("--root", default="/", help="점검할 파일시스템 루트(오프라인 사본 분석용, 기본 /)")
    parser.add_argument("--out", default=None, help="보고서 디렉터리(기본 ./php2shell_report_<호스트>)")
    parser.add_argument("--webroot", action="append", help="웹서버 설정 외에 추가로 검사할 웹루트(여러 번 지정 가능)")
    parser.add_argument("--remote-json", action="append", help="php2shell_remote.py --json 결과 파일(여러 번 지정 가능)")
    parser.add_argument("--since", default=FIRST_SEEN, help=f"이 날짜 이후 변경된 .php를 표시(기본 {FIRST_SEEN})")
    args = parser.parse_args()

    host = Host(args.root)
    if not host.isdir("/etc"):
        print(f"오류: {args.root} 아래에 /etc가 없습니다.", file=sys.stderr)
        return 2
    # The hostname comes from the inspected system, so it must not steer where the report is written.
    hostname = (host.read_text("/etc/hostname") or "").strip() or socket.gethostname()
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", hostname).strip(".") or "host"
    args.out = os.path.abspath(args.out or f"php2shell_report_{safe}")
    try:
        rep = build_report(host, args)
        os.makedirs(args.out, exist_ok=True)
        with open(os.path.join(args.out, "report.json"), "w", encoding="utf-8") as f:
            json.dump(rep, f, ensure_ascii=False, indent=2)
        with open(os.path.join(args.out, "report_ko.md"), "w", encoding="utf-8") as f:
            f.write(render_md(rep))
        with open(os.path.join(args.out, "report.html"), "w", encoding="utf-8") as f:
            f.write(render_html(rep))
    except Exception as exc:  # exit 1 means "reachable"; any failure must map to 2
        print(f"오류: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    s = rep["summary"]
    print(f"서빙 경로 {s['units']}개 · 도달가능 {s['reachable']} · 완화됨(임시) {s['mitigated']} · "
          f"판정보류 {s['undetermined']} · 패치됨 {s['patched']} · 침해 확인 항목 {s['compromise_checks']}")
    print(f"보고서: {args.out}")
    if not s["units"]:
        print("경고: PHP 서빙 경로를 찾지 못했습니다. 지원하지 않는 배치이거나 설정을 읽지 못했을 수 있으며, "
              "'도달가능 0건'은 안전을 뜻하지 않습니다.", file=sys.stderr)
        return 2
    if s["reachable"]:
        return 1
    return 3 if s["undetermined"] else 0


if __name__ == "__main__":
    sys.exit(main())
