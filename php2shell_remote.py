#!/usr/bin/env python3
"""Non-invasive remote PHP exposure checker.

This tool deliberately does not send multipart, SOAP, fatal-error, session, or
code-execution payloads. It only performs a bounded HTTP GET and evaluates
explicitly disclosed PHP version information.

Exit codes: 0 = not_vulnerable_by_version, 1 = likely_vulnerable, 2 = error/invalid,
3 = unknown/not_detected (could not judge; not the same as "no finding").

Output language: --lang ko|en|ja. status is a language-neutral code; reason and notes follow
--lang. Give php2shell_host.py the same --lang, since its report quotes reason verbatim.
"""

from __future__ import annotations

import argparse
import http.client
import json
import re
import ssl
import sys
import time
from dataclasses import asdict, dataclass, field
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


# PHP2Shell (CVE-2026-109618 / CVE-2026-109619) fixed releases, per PHP_취약점_동향_2026-10.md §2.
# 7.4 / 8.0 / 8.1 have no official release, only source backports (PHP-x.y-CVE-2026-109618-109619).
FIXED = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}
OLDEST_SUPPORTED = min(FIXED)
VERSION_RE = re.compile(r"(?:PHP/|PHP[- ]?)((?:\d+\.){1,2}\d+)", re.I)
PHP_MARKER_RE = re.compile(r"\bphp\b|php-fpm|mod_php|x-powered-by", re.I)
READ_CHUNK = 8192

# --- i18n -------------------------------------------------------------------
# User-facing sentences live in MESSAGES (end of file), keyed by meaning.
LANGS = ("ko", "en", "ja")
LANG = "ko"


def t(key: str, **kw) -> str:
    """Message in the current language; falls back to ko, then to the key (never crashes)."""
    s = MESSAGES.get(LANG, {}).get(key) or MESSAGES["ko"].get(key, key)
    return s.format(**kw)


def set_lang(lang: str) -> None:
    global LANG
    LANG = lang if lang in LANGS else "ko"


@dataclass
class Result:
    target: str
    status: str
    reason: str
    http_status: Optional[int] = None
    detected_version: Optional[str] = None
    version_source: Optional[str] = None
    server: Optional[str] = None
    powered_by: Optional[str] = None
    final_url: Optional[str] = None
    redirects: int = 0
    notes: list[str] = field(default_factory=list)


class RedirectTracker(HTTPRedirectHandler):
    """Records every followed redirect so the result shows which server was judged."""

    def __init__(self) -> None:
        self.hops: list[str] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            self.hops.append(newurl)
        return new


def parse_version(value: str) -> tuple[int, ...]:
    return tuple(int(x) for x in value.split("."))


def version_from_headers(headers) -> tuple[Optional[str], Optional[str]]:
    for name in ("X-Powered-By", "Server"):
        for value in headers.get_all(name) or []:
            match = VERSION_RE.search(value)
            if match:
                return match.group(1), name
    return None, None


def read_bounded(response, max_bytes: int, deadline: float) -> tuple[bytes, bool]:
    """Read up to max_bytes, stopping at deadline. Returns (body, truncated_by_time).

    The socket timeout still bounds each recv, so the worst case is deadline + timeout.
    """
    # read(n) blocks until n bytes arrive; read1 returns whatever is buffered, so the
    # deadline is re-checked after every recv.
    read = getattr(response, "read1", response.read)
    chunks: list[bytes] = []
    remaining = max_bytes
    while remaining > 0:
        if time.monotonic() >= deadline:
            return b"".join(chunks), True
        chunk = read(min(READ_CHUNK, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks), False


def judge(version: str) -> tuple[str, str]:
    current = parse_version(version)
    if len(current) < 3:
        return "unknown", t("judge.no_patch", version=version)
    branch = current[:2]
    fixed = FIXED.get(branch)
    if fixed is None:
        if branch < OLDEST_SUPPORTED:
            return "likely_vulnerable", t("judge.eol", version=version)
        return "unknown", t("judge.unknown_branch")
    fixed_str = ".".join(map(str, fixed))
    if current < fixed:
        return "likely_vulnerable", t("judge.below", version=version, fixed=fixed_str)
    return "not_vulnerable_by_version", t("judge.at_or_above", version=version, fixed=fixed_str)


def evaluate(url: str, response, http_status: int, hops: list[str], max_bytes: int, deadline: float) -> Result:
    headers = response.headers
    body_bytes, truncated = read_bounded(response, max_bytes, deadline)
    body = body_bytes.decode("utf-8", errors="replace")
    version, source = version_from_headers(headers)
    server = headers.get("Server")
    powered = headers.get("X-Powered-By")

    notes = [t("note.get_only")]
    if truncated:
        notes.append(t("note.truncated"))
    if hops:
        original = urlparse(url)
        final = urlparse(hops[-1])
        notes.append(t("note.redirects", n=len(hops), final=hops[-1]))
        if final.hostname != original.hostname:
            notes.append(t("note.other_host"))
        if original.scheme == "https" and final.scheme == "http":
            notes.append(t("note.downgrade"))

    result = Result(
        target=url,
        status="",
        reason="",
        http_status=http_status,
        server=server,
        powered_by=powered,
        final_url=hops[-1] if hops else url,
        redirects=len(hops),
        notes=notes,
    )

    header_marker = bool(version or PHP_MARKER_RE.search(f"{server or ''} {powered or ''}"))
    body_marker = bool(PHP_MARKER_RE.search(body))
    if not header_marker and not body_marker:
        result.status = "not_detected"
        result.reason = t("reason.not_detected")
        return result
    if not version:
        if not header_marker:
            notes.append(t("note.body_only"))
        notes.append(t("note.no_version"))
        notes.append(t("note.no_config"))
        result.status = "unknown"
        result.reason = t("reason.no_version")
        return result

    result.status, result.reason = judge(version)
    result.detected_version = version
    result.version_source = source
    notes.append(t("note.version_only"))
    return result


def build_tls_context(verify_tls: bool, cafile: Optional[str]) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if not verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    elif cafile:
        # Added on top of the system trust store, e.g. to supply an intermediate CA a
        # server forgets to send. AIA "CA Issuers" downloads are usually DER, so accept both.
        with open(cafile, "rb") as f:
            data = f.read()
        if b"-----BEGIN CERTIFICATE-----" in data:
            context.load_verify_locations(cadata=data.decode("ascii"))
        else:
            context.load_verify_locations(cadata=data)
    return context


def check(url: str, timeout: float, verify_tls: bool, max_bytes: int, cafile: Optional[str] = None) -> Result:
    try:
        parsed = urlparse(url)
        parsed.port  # raises ValueError for a malformed port
    except ValueError:
        parsed = None
    if parsed is None or parsed.scheme not in ("http", "https") or not parsed.netloc:
        return Result(url, "invalid", t("reason.bad_url"))

    request = Request(
        url,
        headers={"User-Agent": "php2shell-check-remote/1.0", "Accept": "text/html,*/*;q=0.1"},
        method="GET",
    )
    try:
        context = build_tls_context(verify_tls, cafile)
    except (OSError, ValueError) as exc:
        return Result(url, "invalid", t("reason.bad_cafile", error=exc))
    tracker = RedirectTracker()
    opener = build_opener(tracker, HTTPSHandler(context=context))
    deadline = time.monotonic() + timeout
    try:
        try:
            response = opener.open(request, timeout=timeout)
        except HTTPError as exc:
            # Non-2xx responses still carry headers (X-Powered-By is common on 403/404/500).
            with exc:
                result = evaluate(url, exc, exc.code, tracker.hops, max_bytes, deadline)
            result.notes.append(t("note.http_error", code=exc.code, reason=exc.reason))
            return result
        with response:
            return evaluate(url, response, response.status, tracker.hops, max_bytes, deadline)
    except (OSError, http.client.HTTPException, ValueError) as exc:
        result = Result(url, "error", t("reason.connect", error=exc), redirects=len(tracker.hops))
        reason = exc.reason if isinstance(exc, URLError) else exc
        if isinstance(reason, ssl.SSLCertVerificationError) and reason.verify_code == 20:
            # X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY: typically the server omits its
            # intermediate CA. Browsers recover via AIA fetching; OpenSSL does not.
            result.notes.append(t("note.missing_intermediate"))
        return result


def main() -> int:
    # A console code page that lacks a character (e.g. "·" on cp932) must not turn into a
    # traceback: exit 1 is a verdict.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    # --lang must be known before the parser is built so that --help is localized too.
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--lang", default="ko")
    set_lang(pre.parse_known_args()[0].lang)

    parser = argparse.ArgumentParser(description=t("cli.desc"))
    parser.add_argument("url", help=t("cli.url"))
    parser.add_argument("--timeout", type=float, default=8.0, help=t("cli.timeout"))
    parser.add_argument("--max-bytes", type=int, default=262144, help=t("cli.max_bytes"))
    parser.add_argument("--insecure", action="store_true", help=t("cli.insecure"))
    parser.add_argument("--cafile", help=t("cli.cafile"))
    parser.add_argument("--json", action="store_true", help=t("cli.json"))
    parser.add_argument("--lang", choices=LANGS, default="ko", help=t("cli.lang"))
    args = parser.parse_args()
    try:
        result = check(args.url, max(0.1, args.timeout), not args.insecure, max(1024, args.max_bytes), args.cafile)
    except Exception as exc:  # exit 1 means "likely_vulnerable"; any failure must map to 2
        print(t("cli.error", kind=type(exc).__name__, msg=exc), file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(asdict(result), ensure_ascii=False, indent=2))
    else:
        print(t("out.status", status=result.status))
        print(t("out.reason", reason=result.reason))
        if result.http_status:
            print(f"HTTP: {result.http_status}")
        if result.final_url and result.final_url != result.target:
            print(t("out.final_url", url=result.final_url, n=result.redirects))
        if result.server:
            print(f"Server: {result.server}")
        if result.powered_by:
            print(f"X-Powered-By: {result.powered_by}")
        if result.detected_version:
            print(t("out.php", version=result.detected_version, source=result.version_source))
        for note in result.notes:
            print(f"- {note}")
    if result.status in ("error", "invalid"):
        return 2
    return {"likely_vulnerable": 1, "not_vulnerable_by_version": 0}.get(result.status, 3)


# ---------------------------------------------------------------------------
# Message catalog. Placeholders are str.format fields; literal braces must be doubled.
# Every language has exactly the same keys and, per key, the same placeholders.
# ---------------------------------------------------------------------------

MESSAGES = {
    "ko": {
        # verdict reasons
        "judge.no_patch": "PHP {version}은 패치 번호가 공개되지 않아 수정 여부를 판정할 수 없습니다.",
        "judge.eol": "PHP {version}은 공식 수정 릴리스가 없는 지원 종료(EOL) 브랜치입니다. 벤더 백포트 적용 여부를 확인해야 합니다.",
        "judge.unknown_branch": "지원 기준표에 없는 PHP 브랜치입니다. 패치 상태를 원격으로 확정할 수 없습니다.",
        "judge.below": "PHP {version}은 문서의 수정 버전 {fixed} 미만입니다.",
        "judge.at_or_above": "PHP {version}은 문서의 수정 기준 {fixed} 이상입니다.",
        "reason.not_detected": "응답에서 PHP 사용 흔적을 찾지 못했습니다.",
        "reason.no_version": "PHP 버전이 공개되지 않았습니다.",
        "reason.bad_url": "URL은 http:// 또는 https:// 형식이어야 합니다.",
        "reason.bad_cafile": "--cafile을 읽을 수 없습니다: {error}",
        "reason.connect": "연결 실패: {error}",
        # notes
        "note.get_only": "비파괴적 GET 요청만 수행했습니다.",
        "note.truncated": "제한 시간 내에 본문을 다 읽지 못해 일부만 검사했습니다.",
        "note.redirects": "리다이렉트 {n}회를 따라가 최종 응답({final})을 판정했습니다.",
        "note.other_host": "최종 응답이 원래와 다른 호스트입니다. 대상 서버를 판정한 것이 아닐 수 있습니다.",
        "note.downgrade": "https에서 http로 다운그레이드되었습니다.",
        "note.body_only": "PHP 흔적이 본문에만 있습니다(예: .php 링크). 근거가 약합니다.",
        "note.no_version": "PHP 흔적은 있으나 버전이 공개되지 않아 원격 판정이 불가능합니다.",
        "note.no_config": "SAPI와 session.upload_progress/fatal_error_backtraces 설정은 이 방식으로 확인할 수 없습니다.",
        "note.version_only": "버전 판정만으로 실제 도달 가능성이나 배포판 백포트를 확정할 수 없습니다.",
        "note.http_error": "HTTP 오류 응답({code} {reason})의 헤더로 판정했습니다.",
        "note.missing_intermediate": "서버가 중간 CA 인증서를 보내지 않았을 가능성이 큽니다(openssl s_client -showcerts로 확인). 인증서의 AIA 'CA Issuers' URL에서 중간 CA를 받아 --cafile로 지정하거나, 검증을 생략하려면 --insecure를 쓰십시오.",
        # command line
        "cli.desc": "PHP 취약점 비파괴 원격 점검기",
        "cli.url": "점검 대상 URL (예: https://example.com/)",
        "cli.timeout": "전체 제한 시간(초, 기본 8)",
        "cli.max_bytes": "읽을 응답 본문 최대 바이트(기본 256KiB)",
        "cli.insecure": "HTTPS 인증서 검증 생략(내부 테스트에서만 사용)",
        "cli.cafile": "시스템 신뢰 저장소에 추가할 CA/중간 CA 인증서 파일(PEM 또는 DER)",
        "cli.json": "JSON으로 출력",
        "cli.lang": "출력 언어 ko|en|ja (기본 ko). php2shell_host.py 에도 같은 언어를 지정하십시오",
        "cli.error": "오류: {kind}: {msg}",
        "out.status": "판정: {status}",
        "out.reason": "사유: {reason}",
        "out.final_url": "최종 URL: {url} (리다이렉트 {n}회)",
        "out.php": "PHP: {version} (출처: {source})",
    },
    "en": {
        # verdict reasons
        "judge.no_patch": "PHP {version} does not disclose a patch number, so whether it is fixed cannot be determined.",
        "judge.eol": "PHP {version} is an end-of-life (EOL) branch with no official fixed release. Check whether a vendor backport is applied.",
        "judge.unknown_branch": "This PHP branch is not in the support reference table. The patch status cannot be confirmed remotely.",
        "judge.below": "PHP {version} is below the fixed version {fixed} in the document.",
        "judge.at_or_above": "PHP {version} is at or above the fixed version {fixed} in the document.",
        "reason.not_detected": "No sign of PHP was found in the response.",
        "reason.no_version": "The PHP version is not disclosed.",
        "reason.bad_url": "The URL must start with http:// or https://.",
        "reason.bad_cafile": "Cannot read --cafile: {error}",
        "reason.connect": "Connection failed: {error}",
        # notes
        "note.get_only": "Only non-destructive GET requests were made.",
        "note.truncated": "The body could not be read completely within the time limit; only part of it was inspected.",
        "note.redirects": "Followed {n} redirects and assessed the final response ({final}).",
        "note.other_host": "The final response is from a different host than the original. The target server may not be what was assessed.",
        "note.downgrade": "Downgraded from https to http.",
        "note.body_only": "Signs of PHP appear only in the body (e.g. .php links). The evidence is weak.",
        "note.no_version": "There are signs of PHP, but the version is not disclosed, so a remote verdict is not possible.",
        "note.no_config": "The SAPI and the session.upload_progress/fatal_error_backtraces settings cannot be checked this way.",
        "note.version_only": "A version verdict alone cannot confirm actual reachability or distribution backports.",
        "note.http_error": "Assessed from the headers of an HTTP error response ({code} {reason}).",
        "note.missing_intermediate": "The server most likely did not send the intermediate CA certificate (check with openssl s_client -showcerts). Download the intermediate CA from the certificate's AIA 'CA Issuers' URL and pass it with --cafile, or use --insecure to skip verification.",
        # command line
        "cli.desc": "Non-destructive remote checker for PHP vulnerabilities",
        "cli.url": "Target URL (e.g. https://example.com/)",
        "cli.timeout": "Overall time limit (seconds, default 8)",
        "cli.max_bytes": "Maximum response body bytes to read (default 256KiB)",
        "cli.insecure": "Skip HTTPS certificate verification (internal testing only)",
        "cli.cafile": "CA/intermediate CA certificate file to add to the system trust store (PEM or DER)",
        "cli.json": "Output as JSON",
        "cli.lang": "Output language ko|en|ja (default ko). Specify the same language for php2shell_host.py",
        "cli.error": "Error: {kind}: {msg}",
        "out.status": "Verdict: {status}",
        "out.reason": "Reason: {reason}",
        "out.final_url": "Final URL: {url} ({n} redirects)",
        "out.php": "PHP: {version} (source: {source})",
    },
    "ja": {
        # verdict reasons
        "judge.no_patch": "PHP {version} はパッチ番号が公開されていないため、修正の有無を判定できません。",
        "judge.eol": "PHP {version} は公式の修正リリースがないサポート終了（EOL）ブランチです。ベンダーのバックポート適用の有無を確認する必要があります。",
        "judge.unknown_branch": "サポート基準表にないPHPブランチです。パッチ状態をリモートで確定できません。",
        "judge.below": "PHP {version} はドキュメントの修正バージョン {fixed} 未満です。",
        "judge.at_or_above": "PHP {version} はドキュメントの修正基準 {fixed} 以上です。",
        "reason.not_detected": "応答からPHP使用の痕跡が見つかりませんでした。",
        "reason.no_version": "PHPバージョンが公開されていません。",
        "reason.bad_url": "URLは http:// または https:// 形式である必要があります。",
        "reason.bad_cafile": "--cafile を読み取れません: {error}",
        "reason.connect": "接続失敗: {error}",
        # notes
        "note.get_only": "非破壊的なGETリクエストのみを実行しました。",
        "note.truncated": "制限時間内に本文をすべて読み取れなかったため、一部のみを検査しました。",
        "note.redirects": "リダイレクトを{n}回たどり、最終応答（{final}）を判定しました。",
        "note.other_host": "最終応答が元とは異なるホストです。対象サーバーを判定したものではない可能性があります。",
        "note.downgrade": "httpsからhttpにダウングレードされました。",
        "note.body_only": "PHPの痕跡が本文にのみあります（例：.php リンク）。根拠は弱いです。",
        "note.no_version": "PHPの痕跡はありますが、バージョンが公開されていないためリモート判定はできません。",
        "note.no_config": "SAPIと session.upload_progress/fatal_error_backtraces の設定はこの方式では確認できません。",
        "note.version_only": "バージョン判定だけでは、実際の到達可能性やディストリのバックポートを確定できません。",
        "note.http_error": "HTTPエラー応答（{code} {reason}）のヘッダーで判定しました。",
        "note.missing_intermediate": "サーバーが中間CA証明書を送信していない可能性が高いです（openssl s_client -showcerts で確認）。証明書のAIA 'CA Issuers' URLから中間CAを取得して --cafile で指定するか、検証を省略するには --insecure を使用してください。",
        # command line
        "cli.desc": "PHP脆弱性の非破壊リモート点検ツール",
        "cli.url": "点検対象URL（例：https://example.com/）",
        "cli.timeout": "全体の制限時間（秒、既定値 8）",
        "cli.max_bytes": "読み取る応答本文の最大バイト数（既定値 256KiB）",
        "cli.insecure": "HTTPS証明書の検証を省略（内部テストでのみ使用）",
        "cli.cafile": "システムの信頼ストアに追加するCA/中間CA証明書ファイル（PEMまたはDER）",
        "cli.json": "JSONで出力",
        "cli.lang": "出力言語 ko|en|ja（既定値 ko）。php2shell_host.py にも同じ言語を指定してください",
        "cli.error": "エラー: {kind}: {msg}",
        "out.status": "判定: {status}",
        "out.reason": "理由: {reason}",
        "out.final_url": "最終URL: {url}（リダイレクト{n}回）",
        "out.php": "PHP: {version}（出典: {source}）",
    },
}


if __name__ == "__main__":
    sys.exit(main())
