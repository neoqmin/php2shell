# 법적 고지 및 허가된 사용 (Legal Notice & Authorized Use)

> 이 문서는 법률 자문이 아닙니다. 사용 전 소속 조직의 보안·법무 정책을 확인하십시오.
> This document is not legal advice.

## 1. 목적

이 저장소의 도구는 PHP2Shell(CVE-2026-109618 / CVE-2026-109619) 노출 여부를 **방어 목적**으로 확인하기 위한 것입니다. 자산 점검, 패치 적용 확인, 관리자 보고에 사용합니다.

- 공격 페이로드, 익스플로잇 코드, 우회 기법을 포함하지 않습니다.
- `php2shell_remote.py`: 대상 URL에 HTTP `GET` 한 번만 보냅니다(multipart·SOAP·세션 조작·코드 실행 시도 없음).
- `php2shell_host.py`: 서버 안에서 설정·패키지 정보·`/proc`·로그를 읽기만 합니다(명령 실행 0건, 네트워크 요청 0건, 보고서 디렉터리 외 쓰기 없음).

## 2. 허가된 대상에만 사용

**본인이 소유했거나, 소유자에게서 점검 범위·기간을 명시한 서면 허가를 받은 시스템에만** 사용하십시오. 비파괴 GET 요청이라도 허가 없이 타인의 시스템을 체계적으로 점검하면 법적 문제가 될 수 있습니다.

관련 법령 예시(대한민국):

- 「정보통신망 이용촉진 및 정보보호 등에 관한 법률」 제48조(정보통신망 침해행위 등의 금지)
- 「형법」 제314조 제2항(컴퓨터등 장애 업무방해)
- 「개인정보 보호법」 — 로그·보고서에 포함된 IP 등 개인정보 처리

다른 국가에서 사용하거나 다른 국가의 시스템을 점검할 때는 해당 국가의 법(예: 미국 CFAA, 영국 Computer Misuse Act)이 적용됩니다.

## 3. 보증 부인 및 책임 제한

이 소프트웨어는 **"있는 그대로(AS IS)"** 제공되며, 명시적이든 묵시적이든 어떠한 보증도 하지 않습니다. 판정 결과는 공개 정보와 설정 파일에 근거한 **추정**이며 다음을 보장하지 않습니다.

- `not_vulnerable_by_version`, `완화됨(임시)`, `패치됨`이 안전을 뜻하지 않습니다.
- `not_detected`, 침해 징후 없음이 PHP 미사용이나 미침해를 뜻하지 않습니다.
- 판정은 `PHP_취약점_동향_2026-10.md` 작성 시점(2026-10-23)의 공개 정보를 기준으로 하며, 이후 바뀔 수 있습니다.

사용으로 인한 직접·간접 손해, 서비스 장애, 법적 분쟁에 대해 작성자와 기여자는 책임지지 않습니다. 최종 판단과 조치는 사용자와 시스템 관리자의 책임입니다.

## 4. 점검 결과의 취급

생성된 보고서(`report.json`, `report_<lang>.md`, `report_<lang>.html`)와 원격 점검 JSON에는 **대상 시스템의 취약점, 설정 경로, 로그 발췌가 들어 있습니다.**

- 공개 저장소, 이슈, 공개 채널에 올리지 마십시오. `.gitignore`가 기본 출력 경로를 제외합니다.
- 대상 조직 내부의 접근 통제된 경로로만 전달하십시오.
- 로그 발췌에 개인정보가 포함될 수 있으니 전달 전에 확인하십시오.

## 5. 제3자 자료

- `PHP_취약점_동향_2026-10.md`는 공개 보안 권고를 요약한 문서이며 출처를 표기했습니다. 각 원문의 권리는 해당 작성자에게 있습니다.
- 익스플로잇 코드를 담은 저장소는 링크하지 않습니다. 문서의 외부 링크는 참고용입니다. 링크된 제3자 저장소의 내용·안전성·적법성을 검증하거나 보증하지 않으며, 실행 전 직접 검토해야 합니다.
- PHP는 The PHP Group의 상표입니다. 이 프로젝트는 The PHP Group, PHP Foundation 및 문서에 언급된 보안 업체와 관계가 없습니다.

## 6. 취약점·문제 신고

이 도구 자체의 결함이나 오탐·미탐은 저장소 이슈로 알려 주십시오. **특정 시스템의 취약점 정보는 이슈에 쓰지 마십시오.**

---

## English summary

- Defensive use only: exposure assessment and patch verification for CVE-2026-109618 / CVE-2026-109619. No exploit code or payloads are included.
- Use **only on systems you own or are explicitly authorized in writing to test.** Unauthorized scanning may be illegal in your jurisdiction.
- Provided **AS IS, without warranty of any kind.** Results are estimates; "mitigated", "patched" or "not detected" do not mean safe or uncompromised. The authors accept no liability.
- Generated reports contain sensitive vulnerability data. Do not publish them.
- PHP is a trademark of The PHP Group. This project is not affiliated with The PHP Group, the PHP Foundation, or any vendor cited.
