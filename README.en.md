[한국어](README.md) | **English** | [日本語](README.ja.md)

# php2shell-check

Two tools that **non-destructively** check for PHP2Shell (CVE-2026-109618 / CVE-2026-109619) exposure. The decision criteria come from `PHP_취약점_동향_2026-10.en.md` §2.

| Tool | Where it runs | Question it answers |
|---|---|---|
| `php2shell_remote.py` | Anywhere (target URL) | Is the publicly exposed PHP version a vulnerable one — first-pass triage |
| `php2shell_host.py` | On the PHP server | Does an attack path hold given this server's SAPI and effective configuration, and what must be fixed where — administrator report |

**Start from the web:** https://edgebit.co.kr/php2shell/en/ — enter your site's address to get a ready-to-run check command (the address never leaves your browser).

Version alone cannot tell you whether the path is actually reachable. Confirm any server flagged by the remote check with the host-side checker.

> **⚠️ Use only on authorized systems.** Target only systems you own or have written permission to assess. The software is provided without warranty, and the generated report contains the target's vulnerability information, so do not publish it. See [LEGAL.md](LEGAL.md) for details.

## Requirements

- Python 3.8 or later (included as the default Python on Ubuntu 20.04 and later)
- Ubuntu 18.04's default `python3` is 3.6, so `php2shell_host.py` fails with a syntax error (the exit code 1 here comes from Python, it is not a verdict). Run `sudo apt-get install python3.8` and then invoke it with `python3.8`.
- Uses only the standard library, so no extra installation is needed.

## Server-side host check (`php2shell_host.py`)

It only **reads** configuration files, package information (`/var/lib/dpkg/status`, changelogs), `/proc`, and logs. Zero commands executed, zero network requests, and it writes nothing outside the report directory. This fact is recorded in the report's transparency appendix along with the list of files it read.

```bash
# Run on the server (root privileges are needed to read config and logs)
sudo python3 php2shell_host.py

# Also incorporate remote-check results (merges header version and TLS chain issues into the report)
python3 php2shell_remote.py https://example.com/ --json > remote.json
sudo python3 php2shell_host.py --remote-json remote.json

# English / Japanese report (run the remote check in the same language)
python3 php2shell_remote.py https://example.com/ --json --lang en > remote.json
sudo python3 php2shell_host.py --remote-json remote.json --lang en

# Add a webroot not present in the web server config, and set the report location
sudo python3 php2shell_host.py --webroot /srv/app --out /tmp/php2shell_report

# Analyze a copy of the server filesystem offline
python3 php2shell_host.py --root /mnt/server-copy
```

| Option | Default | Description |
|---|---|---|
| `--root` | `/` | Filesystem root to inspect (for analyzing a copy) |
| `--out` | `./php2shell_report_<host>` | Report directory |
| `--webroot` | none | Additional webroot to inspect (can be specified repeatedly) |
| `--remote-json` | none | Output of `php2shell_remote.py --json` (can be specified repeatedly) |
| `--since` | `2026-10-17` | Flag `.php` files changed after this date as items to verify for compromise (date of first observed attack) |
| `--lang` | `ko` | Language of the report and console output (`ko`, `en`, `ja`). The report quotes the remote result's reason verbatim, so run `php2shell_remote.py` with the same `--lang`. |

### Output

`report.json` (machine-readable), `report_<lang>.md` (for attaching to mail/issues), `report_<lang>.html` (for A4 printing), where `<lang>` is the `--lang` value. Code values in `report.json` (`verdict`, `priority`, `version_status`, …) are language neutral; prose fields (`rationale`, `notes`, …) are written in the `--lang` language. For compatibility the verdict label field keeps the name `verdict_ko`; its value is in the `--lang` language. Citations of the basis document (`DOC:NN`) point at the translation for that language, which keeps the original's line numbers. Report structure: summary → inspection targets (serving paths) → per-CVE verdicts and supporting paths → remediation (file/line level, verification commands, impact) → indicators of compromise (needs verification) → transparency appendix.

### Verdicts

| Verdict | Meaning |
|---|---|
| Reachable | The preconditions of the attack path confirmed by the document hold given this server's SAPI and effective configuration |
| Mitigated (temporary) | A temporary mitigation from the document is applied at a stage before request parsing (php.ini, pool `php_admin_value`, web server config). **Not safe** — configuration alone does not fully mitigate (document line 96) |
| Undetermined | Insufficient evidence, failed to read config, or service unused. This is not "unreachable" |
| Patched | At or above the fixed version, or the package changelog records a backport of both CVEs |

Conditions checked: SAPI (mod_php/FPM), `memory_limit` (including whether it is locked), `post_max_size` / `upload_max_filesize`, nginx `client_max_body_size`, `session.upload_progress.enabled`, `fatal_error_backtraces` (8.5), `expose_php`, **mitigations that are set but ineffective** such as `.user.ini` / `ini_set()`, no restart after a config change (estimated from file mtime), TLS certificate chain, logs of abnormal worker termination / memory exhaustion, and `.php` files changed after the date of first observed attack.

Exit codes: `0` nothing reachable and nothing undetermined, `1` one or more reachable, `2` error or no PHP serving path found at all (may be an unsupported deployment), `3` nothing reachable but something undetermined.

At the end of the report there is guidance on how to handle a running legacy server until it can be upgraded (what to do today → obtain the package → zero-downtime upgrade path → when that is impossible → when you find it on another organization's server).

### Limitations

- The effective values are computed from configuration files, so they may differ from the actual values of the running process.
- Apache `php_value` / `php_admin_value` are treated globally, without distinguishing VirtualHost / Directory. `.htaccess` is not interpreted for `AllowOverride`, so only risk-increasing values are reflected.
- Official Docker `php:*-apache` images are recognized by reading the version from `php_version.h`, but official `php:*-fpm` images (`/usr/local/etc/php`) and RHEL mod_php are not yet recognized as serving paths. In that case it ends with zero paths and returns exit code 2.
- When multiple web server configs route to a single FPM pool, the nginx `PHP_VALUE` values are merged for the verdict.
- In `--root` analysis, if the directory itself is an absolute-path symlink, a glob can see outside the copy.
- RHEL-family package versions cannot be checked. php-cgi, LiteSpeed, and FrankenPHP are not inspected.
- Exploitation success conditions (memory layout, worker reuse: CVSS `AC:H/AT:P`) are not assessed.
- When developing/testing on Windows, if you put web-shell-like strings in test fixtures, Windows Defender quarantines the files.

## Remote check (`php2shell_remote.py`)

It sends only a single HTTP `GET` to the target URL (following redirects), with no attack payload, no multipart upload, no SOAP request, no session manipulation, and no code execution attempt.

### Usage

```bash
python3 php2shell_remote.py <URL> [--timeout seconds] [--max-bytes bytes] [--cafile file] [--insecure] [--json]
```

| Option | Default | Description |
|---|---|---|
| `URL` | (required) | Target to check. Must start with `http://` or `https://`. |
| `--timeout` | `8` | Overall time limit from connection to reading the body (seconds). Minimum 0.1. A single socket receive can also wait the same amount, so in the worst case it takes about twice this value. |
| `--max-bytes` | `262144` | Maximum response body size to read (256KiB). Minimum 1024. |
| `--cafile` | none | A CA / intermediate CA certificate file to trust **in addition to** the system trust store. PEM and DER both work. Verification is kept. |
| `--insecure` | off | Skips HTTPS certificate / hostname verification. Use only on internal test servers with a private certificate. Takes precedence over `--cafile`. |
| `--json` | off | Outputs the result as JSON. |
| `--lang` | `ko` | Language of `reason`, `notes` and console output (`ko`, `en`, `ja`). `status` is a language-neutral code. |

### Examples

```bash
# Basic check
python3 php2shell_remote.py https://example.com/

# JSON output (for parsing by another tool)
python3 php2shell_remote.py https://example.com/ --json

# Internal server with a private certificate, allowing slow responses
python3 php2shell_remote.py https://intranet.local/ --insecure --timeout 20

# Batch-check multiple targets (targets.txt: one URL per line)
while read -r url; do
  python3 php2shell_remote.py "$url" --json
done < targets.txt
```

### HTTPS certificate error (`unable to get local issuer certificate`)

If the site opens in a browser but this tool gives the error above, it is usually a server misconfiguration where the server does not send the intermediate CA certificate. The browser fetches the intermediate CA itself from the certificate's AIA address, but Python (OpenSSL) does not. In that case the tool prints guidance in `notes`.

```bash
# 1) Check the chain the server sends: if only "0 s:" appears, the intermediate CA is missing
openssl s_client -connect example.com:443 -servername example.com -showcerts </dev/null

# 2) Check the leaf certificate's AIA "CA Issuers" URL
openssl s_client -connect example.com:443 -servername example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -ext authorityInfoAccess

# 3) Fetch the intermediate CA from that URL and pass it with --cafile (DER can be used as-is)
curl -o intermediate.crt http://<CA Issuers URL>
python3 php2shell_remote.py https://example.com/ --cafile intermediate.crt
```

Unlike `--insecure`, `--cafile` keeps certificate verification. The real fix is to configure the fullchain (leaf + intermediate CA) on the server; since this omission also breaks API clients and monitoring tools the same way, it is worth reporting separately.

If Korean text is garbled on Windows, set `PYTHONIOENCODING=utf-8`, or run `$env:PYTHONIOENCODING='utf-8'` in PowerShell before running it.

### Example output

```text
Verdict: likely_vulnerable
Reason: PHP 8.2.10 is below the fixed version 8.2.35 in the document.
HTTP: 403
X-Powered-By: PHP/8.2.10
PHP: 8.2.10 (source: X-Powered-By)
- Only non-destructive GET requests were made.
- A version verdict alone cannot confirm actual reachability or distribution backports.
- Assessed from the headers of an HTTP error response (403 Forbidden).
```

JSON output fields: `target`, `status`, `reason`, `http_status`, `detected_version`, `version_source`, `server`, `powered_by`, `final_url`, `redirects`, `notes`.

### Verdict meanings

| Verdict | Meaning |
|---|---|
| `likely_vulnerable` | The publicly exposed PHP version is below the document's fixed version, or is an EOL branch (below 8.2) with no official fix release |
| `not_vulnerable_by_version` | The publicly exposed version is at or above the fixed baseline |
| `unknown` | There are traces of PHP but the version is not disclosed, only partially disclosed like `8.3` without a patch number, or a branch newer than the baseline table |
| `not_detected` | No trace of PHP found in the response. This does not mean PHP is absent |
| `error` | Connection failure, TLS error, malformed response, etc. |
| `invalid` | Malformed URL |

Fixed baseline versions: 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35.

Behaviors that affect the verdict:

- Even for an error response such as 403 / 404 / 500, if the headers contain the PHP version, the verdict is made from that header.
- When a redirect is followed, the final response is judged, recorded in `final_url` and `redirects`. If it crosses to a different host or downgrades from https to http, a warning is left in `notes`.
- If the trace of PHP is only in the body (e.g., a `.php` link), a note is added that the evidence is weak.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | `not_vulnerable_by_version` |
| `1` | `likely_vulnerable` |
| `2` | `error`, `invalid` |
| `3` | `unknown`, `not_detected` — cannot determine |

You can use `1` as a failure condition in CI or scripts. `3` is not "no problem" but "no basis to decide."

### Limitations

In production, a proxy / load balancer may hide the version, and distribution backports, SAPI, `session.upload_progress`, and `fatal_error_backtraces` cannot be confirmed from a remote GET alone. A distribution package (e.g., `8.2.7-1+deb12u5`) may have been fixed via backport even with a low version number, so confirm `likely_vulnerable` against the changelog. Therefore `not_vulnerable_by_version` is a supporting signal for confirming patch application, and the final judgment should be made from the server inventory and package change history. Run it only on your own systems or ones you have explicit permission to assess.

## Validation lab (`lab/`)

It brings up 8 sites with Docker, each differing in PHP version, SAPI, package layout, and mitigation state, and runs both checkers against them. Each site has only a single `index.php`, binds only to `127.0.0.1`, and no attack requests are sent. The access port is the PHP version (7.2.34 → `7234`).

```bash
cd lab
./run.sh                 # Windows Git Bash: PYTHON=python ./run.sh
REPORT_LANG=en ./run.sh  # run with English (en) or Japanese (ja) output
cat out/summary.txt      # per-site remote verdict and host-check summary
docker compose down
```

| Port | Configuration | What it verifies |
|---|---|---|
| 7224 | Ubuntu 18.04 · PHP 7.2.24 · nginx+FPM | EOL branch with no patch, Python 3.6 environment |
| 7234 | Official `php:7.2.34-fpm` · nginx | Last 7.2 release, official-image layout |
| 7403 | Ubuntu 20.04 · PHP 7.4.3 · `.user.ini` mitigation | Source-backport-only branch, detection of an ineffective mitigation |
| 8102 | Ubuntu 22.04 · PHP 8.1.2 · mod_php | Distribution backport discrimination (remote says vulnerable, host says patched) |
| 8306 | Ubuntu 24.04 · PHP 8.3.6 · pool mitigation | Distribution backport, `php_admin_value` mitigation |
| 8336 | Official `php:8.3.36-fpm` · nginx | Fixed version, official-image layout |
| 8426 / 8427 | Official `php:8.4.26/27-apache` | mod_php just before / after the fix |

[docs/sample-report/](docs/sample-report/) is a real report generated from one site (7403) in this lab (`.md`/`.html` as `report_ko`, `report_en`, `report_ja`; `report.json` is ko).

After editing a message catalog, run `python lab/check_i18n.py` to confirm that keys and placeholders match across the three languages.

## Author

Kevin Hwang. Also building [PyAutoFlow](https://pyautoflow.com/), a learning-oriented Windows desktop app for writing, running, and automating Python.

## Attribution request for citations / reporting

When introducing this repository or the sample report in an article, blog, or presentation, please credit the source in the format below. For reporting / citation this is a request, not a legal obligation. When you reproduce or adapt the documentation, attribution is required under [CC BY 4.0](LICENSE-docs.md).

> Source: php2shell-check — Kevin Hwang (https://github.com/neoqmin/php2shell)
> The developer is building PyAutoFlow (https://pyautoflow.com/), a desktop app for learning and automating Python.

## License

- Code (`*.py`, `lab/`): [MIT](LICENSE)
- Documentation (`README.md`, `LEGAL.md`, the reference document, `docs/`): [CC BY 4.0](LICENSE-docs.md) — attribution required when reproducing / adapting

Also see [LEGAL.md](LEGAL.md) for terms of use and limitation of liability.
