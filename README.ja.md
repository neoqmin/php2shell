[한국어](README.md) | [English](README.en.md) | **日本語**

# php2shell-check

PHP2Shell（CVE-2026-109618 / CVE-2026-109619）の露出を**非破壊で**点検する2つのツールです。判定基準は `PHP_취약점_동향_2026-10.ja.md` §2 です。

| ツール | 実行場所 | 答える問い |
|---|---|---|
| `php2shell_remote.py` | どこでも（対象URL） | 公開されているPHPバージョンが脆弱なバージョンか — 一次スクリーニング |
| `php2shell_host.py` | PHPサーバー内 | このサーバーのSAPI・実効設定で攻撃経路が成立するか、何をどこで直すべきか — 管理者レポート |

**Webからすぐに始める：** https://edgebit.co.kr/php2shell/ja/ — サイトのアドレスを入力すると実行用の点検コマンドを作成します（アドレスはブラウザの外に送信されません）。

バージョンだけでは実際に到達可能かはわかりません。リモート点検で引っかかったサーバーは内部点検ツールで確定してください。

> **⚠️ 許可されたシステムにのみ使用してください。** 自己所有であるか、書面で点検許可を得たシステムのみが対象です。本ソフトウェアは無保証で提供され、生成されるレポートには対象の脆弱性情報が含まれるため、公開しないでください。詳細は [LEGAL.md](LEGAL.md) を参照してください。

## 要件

- Python 3.8 以上（Ubuntu 20.04 以降は既定のPythonとして同梱）
- Ubuntu 18.04 の既定の `python3` は 3.6 のため、`php2shell_host.py` は構文エラーで実行できません（このときの終了コード 1 は Python が出したもので、判定ではありません）。`sudo apt-get install python3.8` の後、`python3.8` で実行してください。
- 標準ライブラリのみを使用するため、追加インストールは不要です。

## サーバー内部点検（`php2shell_host.py`）

設定ファイル・パッケージ情報（`/var/lib/dpkg/status`、changelog）・`/proc`・ログを**読み取るだけ**です。コマンド実行0件、ネットワーク要求0件で、レポートディレクトリ以外には何も書き込みません。この事実は、読み取ったファイルの一覧とともにレポートの透明性付録に記録されます。

```bash
# サーバー上で実行（設定・ログを読むには root 権限が必要）
sudo python3 php2shell_host.py

# リモート点検結果も反映（ヘッダーのバージョン・TLSチェーンの問題をレポートに統合）
python3 php2shell_remote.py https://example.com/ --json > remote.json
sudo python3 php2shell_host.py --remote-json remote.json

# 英語・日本語のレポート（リモート点検も同じ言語で実行）
python3 php2shell_remote.py https://example.com/ --json --lang ja > remote.json
sudo python3 php2shell_host.py --remote-json remote.json --lang ja

# Webサーバー設定にないwebrootを追加し、レポートの保存先を指定
sudo python3 php2shell_host.py --webroot /srv/app --out /tmp/php2shell_report

# サーバーのファイルシステムのコピーをオフライン解析
python3 php2shell_host.py --root /mnt/server-copy
```

| オプション | 既定値 | 説明 |
|---|---|---|
| `--root` | `/` | 点検するファイルシステムのルート（コピー解析用） |
| `--out` | `./php2shell_report_<ホスト>` | レポートディレクトリ |
| `--webroot` | なし | 追加で検査するwebroot（繰り返し指定可能） |
| `--remote-json` | なし | `php2shell_remote.py --json` の結果（繰り返し指定可能） |
| `--since` | `2026-10-17` | この日付以降に変更された `.php` を侵害確認項目として表示（最初の攻撃観測日） |
| `--lang` | `ko` | レポート・画面出力の言語（`ko`・`en`・`ja`）。レポートはリモート結果の理由文をそのまま引用するため、`php2shell_remote.py` も同じ `--lang` で実行してください。 |

### 成果物

`report.json`（機械可読）、`report_<lang>.md`（メール・Issue添付用）、`report_<lang>.html`（A4印刷用）。`<lang>` は `--lang` の値です。`report.json` のコード値（`verdict`、`priority`、`version_status` など）は言語に依存せず、説明文（`rationale`、`notes` など）は `--lang` の言語で記録されます。互換性のため判定ラベルのフィールド名は `verdict_ko` のままで、値は `--lang` の言語です。根拠ドキュメントの引用（`DOC:NN`）は言語別の翻訳版を指し、翻訳版は原文と行番号が同じです。レポート構成：サマリー → 点検対象（サービング経路）→ CVE別の判定と根拠経路 → 対処事項（ファイル・行単位、確認コマンド、影響）→ 侵害の痕跡（要確認）→ 透明性付録。

### 判定

| 判定 | 意味 |
|---|---|
| 到達可能 | このサーバーのSAPI・実効設定で、ドキュメントが確認した攻撃経路の前提条件が成立 |
| 緩和済み（一時的） | ドキュメントの一時緩和策が、リクエスト解析前の段階（php.ini、pool `php_admin_value`、Webサーバー設定）に適用されている。**安全ではない** — 設定だけでは完全には緩和されない（ドキュメント96行目） |
| 判定保留 | 根拠不足・設定の読み取り失敗・サービス未使用。到達不可という意味ではない |
| パッチ済み | 修正バージョン以上、またはパッケージのchangelogに両CVEのバックポート記録あり |

点検する条件：SAPI（mod_php/FPM）、`memory_limit`（ロックの有無を含む）、`post_max_size`・`upload_max_filesize`、nginx `client_max_body_size`、`session.upload_progress.enabled`、`fatal_error_backtraces`（8.5）、`expose_php`、`.user.ini`・`ini_set()` のように**設定しても効果のない緩和策**、設定変更後の未再起動（ファイルのmtimeから推定）、TLS証明書チェーン、ワーカーの異常終了・メモリ枯渇のログ、最初の攻撃観測日以降に変更された `.php`。

終了コード：`0` 到達可能・判定保留なし、`1` 到達可能1件以上、`2` エラーまたはPHPサービング経路を1つも発見できず（非対応の構成の可能性あり）、`3` 到達可能はないが判定保留がある。

レポートの末尾には、運用中の旧バージョンサーバーをアップグレードまでどう扱うか（今日やること → パッケージの確保 → 無停止アップグレード経路 → 不可能な場合 → 他組織のサーバーで発見した場合）の案内が付きます。

### 制限

- 設定ファイルから計算した実効値のため、実行中のプロセスの実際の値とは異なる場合があります。
- Apache の `php_value`/`php_admin_value` は VirtualHost・Directory の区別なく全体として扱います。`.htaccess` は `AllowOverride` を解釈しないため、リスクを高める値のみを反映します。
- 公式 Docker `php:*-apache` イメージは `php_version.h` からバージョンを読み取って認識しますが、公式 `php:*-fpm` イメージ（`/usr/local/etc/php`）と RHEL の mod_php はまだサービング経路として認識できません。この場合は経路0件で終了し、終了コード2を返します。
- 1つの FPM pool に複数のWebサーバー設定が接続される場合、nginx `PHP_VALUE` を統合して判定します。
- `--root` 解析で、ディレクトリ自体が絶対パスのシンボリックリンクの場合、glob がコピー外を参照することがあります。
- RHEL 系はパッケージバージョンを確認できません。php-cgi、LiteSpeed、FrankenPHP は点検しません。
- エクスプロイト成立条件（メモリレイアウト、ワーカー再利用：CVSS `AC:H/AT:P`）は判定しません。
- Windows で開発・検証する際、テストフィクスチャにWebシェル形式の文字列を入れると Windows Defender がファイルを隔離します。

## リモート点検（`php2shell_remote.py`）

対象URLへ攻撃ペイロード、multipart アップロード、SOAP リクエスト、セッション操作、コード実行の試行は行わず、HTTP `GET` を1回だけ送ります（リダイレクトは追跡します）。

### 使い方

```bash
python3 php2shell_remote.py <URL> [--timeout 秒] [--max-bytes バイト] [--cafile ファイル] [--insecure] [--json]
```

| オプション | 既定値 | 説明 |
|---|---|---|
| `URL` | （必須） | 点検対象。`http://` または `https://` で始まる必要があります。 |
| `--timeout` | `8` | 接続から本文読み取りまでの全体制限時間（秒）。最小 0.1。ソケット受信1回も同じ時間だけ待つことがあり、最悪の場合この値の約2倍かかります。 |
| `--max-bytes` | `262144` | 読み取る応答本文の最大サイズ（256KiB）。最小 1024。 |
| `--cafile` | なし | システム信頼ストアに**追加で**信頼する CA／中間 CA 証明書ファイル。PEM・DER のいずれも可能。検証は維持されます。 |
| `--insecure` | オフ | HTTPS 証明書・ホスト名の検証を省略します。プライベート証明書を使う内部テストサーバーにのみ使用してください。`--cafile` より優先されます。 |
| `--json` | オフ | 結果を JSON で出力します。 |
| `--lang` | `ko` | `reason`・`notes`・画面出力の言語（`ko`・`en`・`ja`）。`status` は言語に依存しないコード値です。 |

### 例

```bash
# 基本の点検
python3 php2shell_remote.py https://example.com/

# JSON 出力（他ツールでパースする場合）
python3 php2shell_remote.py https://example.com/ --json

# プライベート証明書を使う内部サーバー、遅い応答を許容
python3 php2shell_remote.py https://intranet.local/ --insecure --timeout 20

# 複数対象の一括点検（targets.txt: 1行に1URL）
while read -r url; do
  python3 php2shell_remote.py "$url" --json
done < targets.txt
```

### HTTPS 証明書エラー（`unable to get local issuer certificate`）

ブラウザでは開けるのにこのツールで上記のエラーが出る場合、多くはサーバーが中間 CA 証明書を送らない設定ミスです。ブラウザは証明書の AIA アドレスから中間 CA を自ら取得しますが、Python（OpenSSL）はそうしません。この場合、ツールが notes に案内を出力します。

```bash
# 1) サーバーが送るチェーンを確認: "0 s:" が1枚だけなら中間 CA 欠落
openssl s_client -connect example.com:443 -servername example.com -showcerts </dev/null

# 2) leaf 証明書の AIA "CA Issuers" URL を確認
openssl s_client -connect example.com:443 -servername example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -ext authorityInfoAccess

# 3) その URL から中間 CA を取得し --cafile で指定（DER はそのまま使用可能）
curl -o intermediate.crt http://<CA Issuers URL>
python3 php2shell_remote.py https://example.com/ --cafile intermediate.crt
```

`--insecure` とは異なり、`--cafile` は証明書検証を維持します。根本的な解決はサーバーに fullchain（leaf + 中間 CA）を設定することであり、この欠落は API クライアント・監視ツールも同様に失敗させるため、別途報告する価値があります。

Windows で日本語（文字）が化ける場合は、`PYTHONIOENCODING=utf-8` を設定するか、PowerShell で `$env:PYTHONIOENCODING='utf-8'` を実行してから起動してください。

### 出力例

```text
判定: likely_vulnerable
理由: PHP 8.2.10 はドキュメントの修正バージョン 8.2.35 未満です。
HTTP: 403
X-Powered-By: PHP/8.2.10
PHP: 8.2.10（出典: X-Powered-By）
- 非破壊的なGETリクエストのみを実行しました。
- バージョン判定だけでは、実際の到達可能性やディストリのバックポートを確定できません。
- HTTPエラー応答（403 Forbidden）のヘッダーで判定しました。
```

JSON 出力フィールド：`target`、`status`、`reason`、`http_status`、`detected_version`、`version_source`、`server`、`powered_by`、`final_url`、`redirects`、`notes`。

### 判定の意味

| 判定 | 意味 |
|---|---|
| `likely_vulnerable` | 公開されている PHP バージョンがドキュメントの修正バージョンより低いか、公式の修正リリースがない EOL ブランチ（8.2 未満）である |
| `not_vulnerable_by_version` | 公開されているバージョンが修正基準以上である |
| `unknown` | PHP の痕跡はあるがバージョン非公開、パッチ番号なしで `8.3` のように一部のみ公開、または基準表より新しいブランチ |
| `not_detected` | 応答から PHP の痕跡を発見できず。PHP が存在しないという意味ではない |
| `error` | 接続失敗、TLS エラー、不正な応答など |
| `invalid` | URL 形式エラー |

修正基準バージョン：8.5.12 / 8.4.27 / 8.3.36 / 8.2.35。

判定に影響する動作：

- 403・404・500 のようなエラー応答でも、ヘッダーに PHP バージョンがあればそのヘッダーで判定します。
- リダイレクトを追跡した場合は最終応答を判定し、`final_url`、`redirects` に記録されます。別のホストに移るか、https から http にダウングレードされると notes に警告が残ります。
- PHP の痕跡が本文（例：`.php` リンク）にのみある場合、根拠が弱いという note が付きます。

### 終了コード

| コード | 意味 |
|---|---|
| `0` | `not_vulnerable_by_version` |
| `1` | `likely_vulnerable` |
| `2` | `error`、`invalid` |
| `3` | `unknown`、`not_detected` — 判定不可 |

CI やスクリプトで `1` を失敗条件として使えます。`3` は「問題なし」ではなく「判定する根拠がない」です。

### 制限

運用環境ではプロキシ／ロードバランサーがバージョンを隠すことがあり、ディストリビューションのバックポート・SAPI・`session.upload_progress`・`fatal_error_backtraces` はリモート GET だけでは確認できません。ディストリビューションパッケージ（例：`8.2.7-1+deb12u5`）はバージョン番号が低くてもバックポートで修正済みの場合があるため、`likely_vulnerable` は changelog で確認してください。したがって `not_vulnerable_by_version` はパッチ適用確認の補助信号であり、最終判断はサーバーインベントリとパッケージ変更履歴で行ってください。自社または明示的に許可を得たシステムにのみ実行してください。

## 検証ラボ（`lab/`）

PHP バージョン・SAPI・パッケージ構成・緩和状態が異なる8つのサイトを Docker で起動し、2つの点検ツールをまとめて実行します。サイトは `index.php` 1つだけで `127.0.0.1` にのみバインドし、攻撃リクエストは送りません。接続ポートは PHP バージョンです（7.2.34 → `7234`）。

```bash
cd lab
./run.sh                 # Windows Git Bash: PYTHON=python ./run.sh
REPORT_LANG=ja ./run.sh  # 日本語（ja）・英語（en）出力で実行
cat out/summary.txt      # サイト別のリモート判定と内部点検サマリー
docker compose down
```

| ポート | 構成 | 確認する内容 |
|---|---|---|
| 7224 | Ubuntu 18.04 · PHP 7.2.24 · nginx+FPM | パッチのない EOL ブランチ、Python 3.6 環境 |
| 7234 | 公式 `php:7.2.34-fpm` · nginx | 7.2 最終リリース、公式イメージ構成 |
| 7403 | Ubuntu 20.04 · PHP 7.4.3 · `.user.ini` 緩和 | ソースバックポートのみのブランチ、効果のない緩和の検出 |
| 8102 | Ubuntu 22.04 · PHP 8.1.2 · mod_php | ディストリビューションバックポートの判別（リモートは脆弱、内部はパッチ済み） |
| 8306 | Ubuntu 24.04 · PHP 8.3.6 · pool 緩和 | ディストリビューションバックポート、`php_admin_value` 緩和 |
| 8336 | 公式 `php:8.3.36-fpm` · nginx | 修正バージョン、公式イメージ構成 |
| 8426 / 8427 | 公式 `php:8.4.26/27-apache` | 修正直前・直後の mod_php |

[docs/sample-report/](docs/sample-report/) は、このラボの1サイト（7403）で生成した実際のレポートです（`report_ko`・`report_en`・`report_ja` の `.md`/`.html`、`report.json` は ko）。

メッセージカタログを変更したら、`python lab/check_i18n.py` で3言語のキー・placeholder の一致を確認してください。

## 作者

Kevin Hwang。Python を書いて・実行して・自動で回す学習用 Windows デスクトップアプリ [PyAutoFlow](https://pyautoflow.com/) も作っています。

## 引用・報道時の出典表記のお願い

記事・ブログ・発表資料でこのリポジトリやレポート例を紹介する際は、以下の形式で出典を明記してくださるようお願いします。報道・引用については法的義務ではなくお願いです。ドキュメントを複製・翻案する場合は、[CC BY 4.0](LICENSE-docs.md) に従って著作者表示が必要です。

> 出典: php2shell-check — Kevin Hwang (https://github.com/neoqmin/php2shell)
> 開発者は Python 学習・自動化デスクトップアプリ PyAutoFlow(https://pyautoflow.com/) を作っています。

## ライセンス

- コード（`*.py`、`lab/`）：[MIT](LICENSE)
- ドキュメント（`README.md`、`LEGAL.md`、基準ドキュメント、`docs/`）：[CC BY 4.0](LICENSE-docs.md) — 複製・翻案時に著作者表示が必要

使用条件と責任制限については [LEGAL.md](LEGAL.md) もあわせて参照してください。
