# php2shell-check

PHP2Shell(CVE-2026-109618 / CVE-2026-109619) 노출을 **비파괴로** 점검하는 두 도구입니다. 판정 기준은 `PHP_취약점_동향_2026-10.md` §2입니다.

| 도구 | 실행 위치 | 답하는 질문 |
|---|---|---|
| `php2shell_remote.py` | 아무 곳 (대상 URL) | 공개된 PHP 버전이 취약 버전인가 — 1차 선별 |
| `php2shell_host.py` | PHP 서버 안 | 이 서버의 SAPI·실효 설정에서 공격 경로가 성립하는가, 무엇을 어디서 고쳐야 하는가 — 관리자 보고서 |

버전만으로는 실제 도달 여부를 알 수 없습니다. 원격 점검에서 걸린 서버는 내부 점검기로 확정하십시오.

> **⚠️ 허가된 시스템에만 사용하십시오.** 본인 소유이거나 서면으로 점검 허가를 받은 시스템만 대상입니다. 소프트웨어는 보증 없이 제공되며, 생성된 보고서에는 대상의 취약점 정보가 들어 있으므로 공개하지 마십시오. 자세한 내용은 [LEGAL.md](LEGAL.md)를 보십시오.

## 요구 사항

- Python 3.8 이상 (Ubuntu 20.04 기본 Python 포함)
- 표준 라이브러리만 사용하므로 별도 설치는 필요 없습니다.

## 서버 내부 점검 (`php2shell_host.py`)

설정 파일·패키지 정보(`/var/lib/dpkg/status`, changelog)·`/proc`·로그를 **읽기만** 합니다. 명령 실행 0건, 네트워크 요청 0건이며 보고서 디렉터리 외에는 아무것도 쓰지 않습니다. 이 사실은 보고서의 투명성 부록에 읽은 파일 목록과 함께 기록됩니다.

```bash
# 서버에서 실행 (설정·로그를 읽으려면 root 권한 필요)
sudo python3 php2shell_host.py

# 원격 점검 결과를 함께 반영 (헤더 버전·TLS 체인 문제를 보고서에 합침)
python3 php2shell_remote.py https://example.com/ --json > remote.json
sudo python3 php2shell_host.py --remote-json remote.json

# 웹서버 설정에 없는 웹루트 추가, 보고서 위치 지정
sudo python3 php2shell_host.py --webroot /srv/app --out /tmp/php2shell_report

# 서버 파일시스템 사본을 오프라인 분석
python3 php2shell_host.py --root /mnt/server-copy
```

| 옵션 | 기본값 | 설명 |
|---|---|---|
| `--root` | `/` | 점검할 파일시스템 루트(사본 분석용) |
| `--out` | `./php2shell_report_<호스트>` | 보고서 디렉터리 |
| `--webroot` | 없음 | 추가로 검사할 웹루트(반복 지정 가능) |
| `--remote-json` | 없음 | `php2shell_remote.py --json` 결과(반복 지정 가능) |
| `--since` | `2026-10-17` | 이 날짜 이후 변경된 `.php`를 침해 확인 항목으로 표시(첫 공격 관측일) |

### 산출물

`report.json`(기계 판독), `report_ko.md`(메일·이슈 첨부용), `report.html`(A4 인쇄용). 보고서 구성: 요약 → 점검 대상(서빙 경로) → CVE별 판정과 근거 경로 → 조치 사항(파일·줄 단위, 확인 명령, 영향) → 침해 징후(확인 필요) → 투명성 부록.

### 판정

| 판정 | 의미 |
|---|---|
| 도달가능 | 이 서버의 SAPI·실효 설정에서 문서가 확인한 공격 경로의 전제조건이 성립 |
| 완화됨(임시) | 문서의 임시 완화가 요청 파싱 전 단계(php.ini, pool `php_admin_value`, 웹서버 설정)에 적용됨. **안전이 아님** — 설정만으로는 완전히 완화되지 않음(문서 96행) |
| 판정보류 | 근거 부족·설정 읽기 실패·서비스 미사용. 도달불가가 아님 |
| 패치됨 | 수정 버전 이상 또는 패키지 changelog에 두 CVE 백포트 기록 |

점검하는 조건: SAPI(mod_php/FPM), `memory_limit`(잠금 여부 포함), `post_max_size`·`upload_max_filesize`, nginx `client_max_body_size`, `session.upload_progress.enabled`, `fatal_error_backtraces`(8.5), `expose_php`, `.user.ini`·`ini_set()`처럼 **설정했지만 효과 없는 완화**, 설정 변경 후 미재시작(파일 mtime 기준 추정), TLS 인증서 체인, 워커 비정상 종료·메모리 고갈 로그, 첫 공격 관측일 이후 변경된 `.php`.

종료 코드: `0` 도달가능·판정보류 없음, `1` 도달가능 1건 이상, `2` 오류 또는 PHP 서빙 경로를 하나도 찾지 못함(지원하지 않는 배치일 수 있음), `3` 도달가능은 없지만 판정보류가 있음.

보고서 말미에는 운영 중인 구버전 서버를 업그레이드 전까지 어떻게 다룰지(오늘 할 일 → 패키지 확보 → 무중단 업그레이드 경로 → 불가능할 때 → 다른 조직 서버에서 발견했을 때) 안내가 붙습니다.

### 한계

- 설정 파일로 계산한 실효값이므로 실행 중인 프로세스의 실제 값과 다를 수 있습니다.
- Apache의 `php_value`/`php_admin_value`는 VirtualHost·Directory 구분 없이 전역으로 취급합니다. `.htaccess`는 `AllowOverride`를 해석하지 않으므로 위험을 높이는 값만 반영합니다.
- 공식 Docker `php` 이미지(`/usr/local/etc/php`)와 RHEL의 mod_php는 아직 서빙 경로로 인식하지 못합니다. 이때는 경로 0개로 끝나며 종료 코드 2를 돌려줍니다.
- 한 FPM pool에 여러 웹서버 설정이 연결되면 nginx `PHP_VALUE`를 합쳐서 판정합니다.
- `--root` 분석에서 디렉터리 자체가 절대경로 심링크이면 glob이 사본 밖을 볼 수 있습니다.
- RHEL 계열은 패키지 버전을 확인하지 못합니다. php-cgi, LiteSpeed, FrankenPHP는 점검하지 않습니다.
- 익스플로잇 성공 조건(메모리 레이아웃, 워커 재사용: CVSS `AC:H/AT:P`)은 판정하지 않습니다.
- Windows에서 개발·검증할 때 테스트 픽스처에 웹셸 형태의 문자열을 넣으면 Windows Defender가 파일을 격리합니다.

## 원격 점검 (`php2shell_remote.py`)

대상 URL에 공격 페이로드, multipart 업로드, SOAP 요청, 세션 조작, 코드 실행 시도는 하지 않고 HTTP `GET` 한 번만 보냅니다(리다이렉트는 따라갑니다).

### 사용법

```bash
python3 php2shell_remote.py <URL> [--timeout 초] [--max-bytes 바이트] [--cafile 파일] [--insecure] [--json]
```

| 옵션 | 기본값 | 설명 |
|---|---|---|
| `URL` | (필수) | 점검 대상. `http://` 또는 `https://`로 시작해야 합니다. |
| `--timeout` | `8` | 연결부터 본문 읽기까지 전체 제한 시간(초). 최소 0.1. 소켓 수신 1회도 같은 시간만큼 대기할 수 있어 최악의 경우 이 값의 약 2배가 걸립니다. |
| `--max-bytes` | `262144` | 읽을 응답 본문 최대 크기(256KiB). 최소 1024. |
| `--cafile` | 없음 | 시스템 신뢰 저장소에 **추가로** 신뢰할 CA/중간 CA 인증서 파일. PEM·DER 모두 가능. 검증은 유지됩니다. |
| `--insecure` | 꺼짐 | HTTPS 인증서·호스트명 검증을 생략합니다. 사설 인증서를 쓰는 내부 테스트 서버에만 사용하십시오. `--cafile`보다 우선합니다. |
| `--json` | 꺼짐 | 결과를 JSON으로 출력합니다. |

### 예시

```bash
# 기본 점검
python3 php2shell_remote.py https://example.com/

# JSON 출력 (다른 도구에서 파싱할 때)
python3 php2shell_remote.py https://example.com/ --json

# 사설 인증서를 쓰는 내부 서버, 느린 응답 허용
python3 php2shell_remote.py https://intranet.local/ --insecure --timeout 20

# 여러 대상 일괄 점검 (targets.txt: 한 줄에 URL 하나)
while read -r url; do
  python3 php2shell_remote.py "$url" --json
done < targets.txt
```

### HTTPS 인증서 오류 (`unable to get local issuer certificate`)

브라우저에서는 열리는데 이 도구에서 위 오류가 나면, 대개 서버가 중간 CA 인증서를 보내지 않는 설정 오류입니다. 브라우저는 인증서의 AIA 주소에서 중간 CA를 스스로 받아 오지만 Python(OpenSSL)은 그렇게 하지 않습니다. 이 경우 도구가 notes에 안내를 출력합니다.

```bash
# 1) 서버가 보내는 체인 확인: "0 s:" 한 장만 나오면 중간 CA 누락
openssl s_client -connect example.com:443 -servername example.com -showcerts </dev/null

# 2) leaf 인증서의 AIA "CA Issuers" URL 확인
openssl s_client -connect example.com:443 -servername example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -ext authorityInfoAccess

# 3) 그 URL에서 중간 CA를 받아 --cafile로 지정 (DER 그대로 사용 가능)
curl -o intermediate.crt http://<CA Issuers URL>
python3 php2shell_remote.py https://example.com/ --cafile intermediate.crt
```

`--insecure`와 달리 `--cafile`은 인증서 검증을 유지합니다. 근본 해결은 서버에 fullchain(leaf + 중간 CA)을 설정하는 것이며, 이 누락은 API 클라이언트·모니터링 도구도 똑같이 실패시키므로 별도로 보고할 만합니다.

Windows에서 한글이 깨지면 `PYTHONIOENCODING=utf-8`을 설정하거나 PowerShell에서 `$env:PYTHONIOENCODING='utf-8'`을 실행한 뒤 돌리십시오.

### 출력 예

```text
판정: likely_vulnerable
사유: PHP 8.2.10은 문서의 수정 버전 8.2.35 미만입니다.
HTTP: 403
X-Powered-By: PHP/8.2.10
PHP: 8.2.10 (출처: X-Powered-By)
- 비파괴적 GET 요청만 수행했습니다.
- 버전 판정만으로 실제 도달 가능성이나 배포판 백포트를 확정할 수 없습니다.
- HTTP 오류 응답(403 Forbidden)의 헤더로 판정했습니다.
```

JSON 출력 필드: `target`, `status`, `reason`, `http_status`, `detected_version`, `version_source`, `server`, `powered_by`, `final_url`, `redirects`, `notes`.

### 판정 의미

| 판정 | 의미 |
|---|---|
| `likely_vulnerable` | 공개된 PHP 버전이 문서의 수정 버전보다 낮거나, 공식 수정 릴리스가 없는 EOL 브랜치(8.2 미만)임 |
| `not_vulnerable_by_version` | 공개된 버전이 수정 기준 이상임 |
| `unknown` | PHP 흔적은 있으나 버전 비공개, 패치 번호 없이 `8.3`처럼 일부만 공개, 또는 기준표보다 새로운 브랜치 |
| `not_detected` | 응답에서 PHP 흔적을 찾지 못함. PHP가 없다는 뜻은 아님 |
| `error` | 연결 실패, TLS 오류, 잘못된 응답 등 |
| `invalid` | URL 형식 오류 |

수정 기준 버전: 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35.

판정에 영향을 주는 동작:

- 403·404·500 같은 오류 응답이라도 헤더에 PHP 버전이 있으면 그 헤더로 판정합니다.
- 리다이렉트를 따라간 경우 최종 응답을 판정하며 `final_url`, `redirects`에 기록됩니다. 다른 호스트로 넘어가거나 https에서 http로 다운그레이드되면 notes에 경고가 남습니다.
- PHP 흔적이 본문(예: `.php` 링크)에만 있으면 근거가 약하다는 note가 붙습니다.

### 종료 코드

| 코드 | 의미 |
|---|---|
| `0` | `not_vulnerable_by_version` |
| `1` | `likely_vulnerable` |
| `2` | `error`, `invalid` |
| `3` | `unknown`, `not_detected` — 판정 불가 |

CI나 스크립트에서 `1`을 실패 조건으로 쓸 수 있습니다. `3`은 "문제없음"이 아니라 "판정할 근거가 없음"입니다.

### 한계

운영 환경에서는 프록시/로드밸런서가 버전을 숨길 수 있고, 배포판 백포트·SAPI·`session.upload_progress`·`fatal_error_backtraces`는 원격 GET만으로 확인할 수 없습니다. 배포판 패키지(예: `8.2.7-1+deb12u5`)는 버전 번호가 낮아도 백포트로 수정됐을 수 있으므로 `likely_vulnerable`은 changelog로 확인하십시오. 따라서 `not_vulnerable_by_version`은 패치 적용 확인의 보조 신호이며, 최종 판단은 서버 인벤토리와 패키지 변경 이력으로 하십시오. 자사 또는 명시적으로 허가받은 시스템에만 실행하십시오.

## 만든 사람

Kevin Hwang. 파이썬을 쓰고·실행하고·자동으로 돌리는 학습용 Windows 데스크톱 앱
[PyAutoFlow](https://pyautoflow.com/)도 만들고 있습니다.

## 라이선스

[MIT](LICENSE). 사용 조건과 책임 제한은 [LEGAL.md](LEGAL.md)를 함께 보십시오.
