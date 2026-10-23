#!/usr/bin/env python3
"""Non-invasive remote PHP exposure checker.

This tool deliberately does not send multipart, SOAP, fatal-error, session, or
code-execution payloads. It only performs a bounded HTTP GET and evaluates
explicitly disclosed PHP version information.

Exit codes: 0 = not_vulnerable_by_version, 1 = likely_vulnerable, 2 = error/invalid,
3 = unknown/not_detected (could not judge; not the same as "no finding").
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
        return "unknown", f"PHP {version}은 패치 번호가 공개되지 않아 수정 여부를 판정할 수 없습니다."
    branch = current[:2]
    fixed = FIXED.get(branch)
    if fixed is None:
        if branch < OLDEST_SUPPORTED:
            return "likely_vulnerable", f"PHP {version}은 공식 수정 릴리스가 없는 지원 종료(EOL) 브랜치입니다. 벤더 백포트 적용 여부를 확인해야 합니다."
        return "unknown", "지원 기준표에 없는 PHP 브랜치입니다. 패치 상태를 원격으로 확정할 수 없습니다."
    fixed_str = ".".join(map(str, fixed))
    if current < fixed:
        return "likely_vulnerable", f"PHP {version}은 문서의 수정 버전 {fixed_str} 미만입니다."
    return "not_vulnerable_by_version", f"PHP {version}은 문서의 수정 기준 {fixed_str} 이상입니다."


def evaluate(url: str, response, http_status: int, hops: list[str], max_bytes: int, deadline: float) -> Result:
    headers = response.headers
    body_bytes, truncated = read_bounded(response, max_bytes, deadline)
    body = body_bytes.decode("utf-8", errors="replace")
    version, source = version_from_headers(headers)
    server = headers.get("Server")
    powered = headers.get("X-Powered-By")

    notes = ["비파괴적 GET 요청만 수행했습니다."]
    if truncated:
        notes.append("제한 시간 내에 본문을 다 읽지 못해 일부만 검사했습니다.")
    if hops:
        original = urlparse(url)
        final = urlparse(hops[-1])
        notes.append(f"리다이렉트 {len(hops)}회를 따라가 최종 응답({hops[-1]})을 판정했습니다.")
        if final.hostname != original.hostname:
            notes.append("최종 응답이 원래와 다른 호스트입니다. 대상 서버를 판정한 것이 아닐 수 있습니다.")
        if original.scheme == "https" and final.scheme == "http":
            notes.append("https에서 http로 다운그레이드되었습니다.")

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
        result.reason = "응답에서 PHP 사용 흔적을 찾지 못했습니다."
        return result
    if not version:
        if not header_marker:
            notes.append("PHP 흔적이 본문에만 있습니다(예: .php 링크). 근거가 약합니다.")
        notes.append("PHP 흔적은 있으나 버전이 공개되지 않아 원격 판정이 불가능합니다.")
        notes.append("SAPI와 session.upload_progress/fatal_error_backtraces 설정은 이 방식으로 확인할 수 없습니다.")
        result.status = "unknown"
        result.reason = "PHP 버전이 공개되지 않았습니다."
        return result

    result.status, result.reason = judge(version)
    result.detected_version = version
    result.version_source = source
    notes.append("버전 판정만으로 실제 도달 가능성이나 배포판 백포트를 확정할 수 없습니다.")
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
        return Result(url, "invalid", "URL은 http:// 또는 https:// 형식이어야 합니다.")

    request = Request(
        url,
        headers={"User-Agent": "php2shell-check-remote/1.0", "Accept": "text/html,*/*;q=0.1"},
        method="GET",
    )
    try:
        context = build_tls_context(verify_tls, cafile)
    except (OSError, ValueError) as exc:
        return Result(url, "invalid", f"--cafile을 읽을 수 없습니다: {exc}")
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
            result.notes.append(f"HTTP 오류 응답({exc.code} {exc.reason})의 헤더로 판정했습니다.")
            return result
        with response:
            return evaluate(url, response, response.status, tracker.hops, max_bytes, deadline)
    except (OSError, http.client.HTTPException, ValueError) as exc:
        result = Result(url, "error", f"연결 실패: {exc}", redirects=len(tracker.hops))
        reason = exc.reason if isinstance(exc, URLError) else exc
        if isinstance(reason, ssl.SSLCertVerificationError) and reason.verify_code == 20:
            # X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY: typically the server omits its
            # intermediate CA. Browsers recover via AIA fetching; OpenSSL does not.
            result.notes.append(
                "서버가 중간 CA 인증서를 보내지 않았을 가능성이 큽니다"
                "(openssl s_client -showcerts로 확인). 인증서의 AIA 'CA Issuers' URL에서 "
                "중간 CA를 받아 --cafile로 지정하거나, 검증을 생략하려면 --insecure를 쓰십시오."
            )
        return result


def main() -> int:
    parser = argparse.ArgumentParser(description="PHP 취약점 비파괴 원격 점검기")
    parser.add_argument("url", help="점검 대상 URL (예: https://example.com/)")
    parser.add_argument("--timeout", type=float, default=8.0, help="전체 제한 시간(초, 기본 8)")
    parser.add_argument("--max-bytes", type=int, default=262144, help="읽을 응답 본문 최대 바이트(기본 256KiB)")
    parser.add_argument("--insecure", action="store_true", help="HTTPS 인증서 검증 생략(내부 테스트에서만 사용)")
    parser.add_argument("--cafile", help="시스템 신뢰 저장소에 추가할 CA/중간 CA 인증서 파일(PEM 또는 DER)")
    parser.add_argument("--json", action="store_true", help="JSON으로 출력")
    args = parser.parse_args()
    try:
        result = check(args.url, max(0.1, args.timeout), not args.insecure, max(1024, args.max_bytes), args.cafile)
    except Exception as exc:  # exit 1 means "likely_vulnerable"; any failure must map to 2
        print(f"오류: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(asdict(result), ensure_ascii=False, indent=2))
    else:
        print(f"판정: {result.status}")
        print(f"사유: {result.reason}")
        if result.http_status:
            print(f"HTTP: {result.http_status}")
        if result.final_url and result.final_url != result.target:
            print(f"최종 URL: {result.final_url} (리다이렉트 {result.redirects}회)")
        if result.server:
            print(f"Server: {result.server}")
        if result.powered_by:
            print(f"X-Powered-By: {result.powered_by}")
        if result.detected_version:
            print(f"PHP: {result.detected_version} (출처: {result.version_source})")
        for note in result.notes:
            print(f"- {note}")
    if result.status in ("error", "invalid"):
        return 2
    return {"likely_vulnerable": 1, "not_vulnerable_by_version": 0}.get(result.status, 3)


if __name__ == "__main__":
    sys.exit(main())
