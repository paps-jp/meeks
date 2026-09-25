# Meeks

URL を共有し、参加者が承認するだけで使える、エンドツーエンド暗号化（E2EE）のグループチャット。
テキスト・ファイル・写真の送受信とビデオ通話ができ、サーバーはメッセージを一切保存しません。

## 仕組み

```
ブラウザ A ──(1) P2P: WebRTC DataChannel / メディア ──────── ブラウザ B
    │        (2) P2P 不可 → TURN 中継（DTLS/SRTP のまま）        │
    │        (3) WebRTC 自体が不可 → WebSocket 中継              │
    └──────────── Meeks サーバー (Go) ─────────────────────────┘
                   ・マッチング（WebSocket シグナリング）
                   ・STUN/TURN（pion/turn を内蔵）
                   ・参加申し込みの保管（暗号鍵は暗号化されたまま）
                   ・IP ログ（2 年保存）
```

| 項目 | 実装 |
|---|---|
| ルーム | `/{ルームID}`（例: `https://meeks.example.com/team-meeting`）。ルーム ID はランダム発行または任意の名前。URL に暗号鍵は含まない。`static` `ws` `r` `healthz` と言語コード（`en` など）は予約語。旧形式の `/r/{ルームID}` は自動で転送する |
| 暗号鍵 | まだ存在しないルームを開いた人の端末で作成。受け取った鍵は localStorage に保存し、同じ URL を開き直すとそのまま復帰する |
| 参加の承認 | 鍵を持たない人が URL を開くと参加申し込みになる。参加者のタイムラインに申し込みカード（［承認］［拒否］と返信欄）が流れ、承認すると暗号鍵が申込者の公開鍵（ECDH P-256）で暗号化されて渡る。誰もオンラインでなくても申し込みと承認結果はサーバーに保管され、次に接続したときに届く。申し込みカードと申込者の画面に同じ確認コードを表示する |
| 承認前のメッセージ | 申込者は承認前から参加者とメッセージをやり取りできる（1 件の申し込みにつき 20 件まで、テキストのみ）。ルームごとの受付用鍵ペアの公開鍵で E2EE にし、秘密鍵は参加者だけが持つ（承認時にルーム鍵と一緒に渡す）。やり取りは承認後もそのまま履歴に残る |
| E2EE | チャット・ファイル・過去ログ・既読、WebRTC のシグナリング（SDP）まで、すべてルーム鍵（AES-256-GCM）で暗号化。サーバーは通信を中継・記録しても内容を読めない |
| 通信経路 | 相手ごとに P2P → TURN 中継 → WebSocket 中継の順で自動選択。参加者一覧に `P2P` / `TURN中継` / `サーバー経由` と表示 |
| 過去ログ | 各端末の IndexedDB に保存。接続のたびに参加者同士で自動同期する（直近 1,000 件のうち相手が持っていないものを送り合う。ファイルは 20MB まで） |
| 既読・未読 | 自分の発言に「既読 N」を表示（カーソルを合わせると既読者名）。画面に表示され、かつウィンドウが前面にあるときに既読とする。未読件数はタブのタイトルに表示し、「ここから未読」の区切り線を出す。相手が不在の間についた既読も、次の同期で届く |
| 多言語 | 日本語・English・한국어・中文・Русский・العربية（右から左）・हिन्दी・Español・বাংলা・Português・Indonesia・Polski・Українська（13 言語）。トップページは `/`（日本語）と `/en` `/ko` …をサーバー側で翻訳済み HTML として配信し、hreflang・sitemap に反映。ルーム画面はトップで選んだ言語かブラウザの言語で表示し、サイドバーで切り替え可能。翻訳は `web/static/i18n/{言語}.json`（サーバーとブラウザで共用） |
| ファイル | 60KB 単位で暗号化して転送（上限 100MB）。画像・動画・音声はプレビュー表示 |
| 通話・画面共有 | WebRTC メッシュ（全員が相互接続）。「通話」メニューから音声通話・ビデオ通話・画面共有を選べる。画面共有は通話と独立して開始／停止でき、共有画面は「〇〇の画面」として別枠で表示（スマホのブラウザなど非対応環境では項目を出さない） |
| IP ログ | 接続・切断・参加申し込み・TURN 認証時の IP / 送信元ポート / 時刻 / ルーム ID のハッシュを JSONL で記録し、730 日経過で自動削除 |

## 起動

Go 1.27 以降が必要です（`go.mod` 準拠）。

```bash
go run . serve -turn-allow-private
```

`http://localhost:8080` を開き「新しいルームを作成」→ 表示された URL を共有します。
（`-turn-allow-private` は同一マシン/LAN での動作確認用です。本番では付けないでください）

ビルド:

```bash
go build -o meeks .
```

### 主なオプション（`meeks serve -h`）

| フラグ | 既定値 | 説明 |
|---|---|---|
| `-addr` | `:8080` | HTTP 待受 |
| `-site-url` | リクエストから推定 | 公開 URL（例: `https://meeks.example.com`）。canonical・OGP・sitemap に使う。本番では指定する |
| `-tls-cert` / `-tls-key` | | HTTPS（localhost 以外でカメラを使うには HTTPS 必須） |
| `-trust-proxy` | false | リバースプロキシの `X-Real-IP` / `X-Forwarded-For` / `X-Real-Port` を信頼 |
| `-max-peers` | 16 | 1 ルームの上限人数 |
| `-iplog-dir` | `data/iplog` | IP ログの保存先 |
| `-iplog-days` | 730 | IP ログ保存日数 |
| `-state-file` | `data/state.json` | ルームの存在と参加申し込みの保存先 |
| `-room-days` | 730 | この日数使われていないルームの登録を削除 |
| `-turn-addr` | `:3478` | STUN/TURN 待受（UDP と TCP） |
| `-turn-public-ip` | `127.0.0.1` | TURN 中継アドレスとして通知するサーバーのグローバル IP |
| `-turn-host` | HTTP の Host | クライアントが STUN/TURN に接続するホスト名 |
| `-turn-secret` | 起動毎にランダム | TURN 認証用の共有シークレット（複数台構成時は固定する） |
| `-turn-max-allocs-per-user` | 30 | 1 人（接続）あたりの同時 TURN 中継数。ブラウザはルームを開いている間、相手ごとに UDP と TCP の中継を確保する |
| `-turn-max-allocs` | 1000 | サーバー全体の同時 TURN 中継数（中継ポート数以下にする） |
| `-turn-relay-min` / `-max` | 49160 / 49200 | TURN 中継に使う UDP ポート範囲 |

## 本番運用

開放するポート: `443/tcp`（HTTPS）、`3478/udp` と `3478/tcp`（STUN/TURN）、`49160-49200/udp`（TURN 中継）。

```bash
./meeks serve -addr 127.0.0.1:8080 -trust-proxy -site-url https://meeks.example.com \
  -turn-public-ip 203.0.113.10 -turn-host meeks.example.com -turn-secret "$TURN_SECRET"
```

nginx の例（送信元ポートは CGNAT 配下の利用者を特定するために必要）:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Real-Port $remote_port;
    proxy_read_timeout 3600s;
}
```

## Docker で設置（既存の Caddy と同居）

`deploy/` に、TLS 終端を既存の Caddy（例: passist の構成）に任せる構成を用意しています。

```bash
git clone https://github.com/paps-jp/meeks && cd meeks/deploy
cp .env.example .env        # PUBLIC_IP、TURN_SECRET（openssl rand -hex 32）、HTTP_ADDR を設定
mkdir -p data && sudo chown 65532:65532 data && sudo chmod 700 data
docker compose up -d --build
```

- コンテナはホストネットワークで動かす（Docker でポート範囲を公開すると 1 ポートごとに docker-proxy が起動し、1,000 ポートでは約 2,000 プロセスになってメモリが足りなくなるため）。HTTP は `HTTP_ADDR`（Caddy の Docker ネットワークのゲートウェイ IP、例 `172.18.0.1:8080`）で待ち受け、UFW でそのネットワークからの接続だけを許可する。`Caddyfile.meeks` のブロックを Caddy の Caddyfile に追記して reload する
- 内蔵 TURN は `3479/tcp,udp` と中継用 `30000-30999/udp`（coturn の 3478 / 49152-65535 や OS の一時ポート 32768〜 と衝突せず、1〜32767 しか指定できないさくらVPS のパケットフィルタにも収まる）。`.env` の `TURN_RELAY_MIN` / `TURN_RELAY_MAX` で変更可。UFW と VPS 事業者のパケットフィルタの両方で開放する
- Cloudflare のプロキシを使う場合、IP は `CF-Connecting-IP` から取得できるが送信元ポートは記録できない。開示請求対応を重視するなら DNS only を推奨
- TURN は UDP のため Cloudflare を通らない。`TURN_HOST` は IP か DNS only のホスト名にする

## Cloudflare TURN（予備の中継）

自前の TURN の後ろに、Cloudflare Realtime TURN を予備として追加できる（ブラウザには自前の TURN を先に渡すので、通常は自前が優先される）。渡すのは UDP 3478 と TLS 443（厳しいファイアウォール向け）のみ。

- `.env` に `CF_TURN_KEY_ID` / `CF_TURN_KEY_TOKEN`（Cloudflare ダッシュボードの Realtime → TURN で作成）を設定する
- 月間上限（`CF_TURN_MONTHLY_GB`、既定 900GB。無料枠は Realtime SFU と共用で 1,000GB）を守るため、`CF_ACCOUNT_ID` と「Account Analytics: Read」権限の API トークン `CF_ANALYTICS_TOKEN` も設定する。**利用量を読めない間は Cloudflare TURN を渡さない**
- 認証情報は 30 分ごとにまとめて発行（有効期限 2 時間）。5 分ごとにアカウント全体の今月の TURN 送信量を確認し、上限に達したら渡すのをやめ、発行済みの認証情報を失効させて使用中の中継も止める。翌月に自動で再開する
- Cloudflare 経由の中継の利用記録（IP 等）は Cloudflare 側にのみ残り、Meeks の IP ログには残らない。映像・音声は端末間で暗号化されたまま
- 秘密情報（`TURN_SECRET` を含む）はコマンドライン引数ではなく環境変数で渡す

## SEO

- トップページ: title / description / canonical / OGP / X（Twitter）カード / 構造化データ（WebApplication）/ manifest。共有用画像は `web/static/img/og.png`（1200×630）
- `robots.txt` と `sitemap.xml` をサーバーが生成（URL は `-site-url`）
- ルームページは `X-Robots-Tag` と meta robots で `noindex, nofollow, noarchive`。robots.txt ではブロックしない（ブロックすると noindex を読めず、URL だけが検索結果に出ることがあるため）

## 発信者情報開示請求への対応

IP ログは `data/iplog/ip-YYYY-MM-DD.jsonl`（UTC、パーミッション 0600）に 1 行 1 イベントで保存されます。
ルーム ID は SHA-256 ハッシュのみ保存するため、請求者から提示されたルーム URL で検索します。

```bash
./meeks lookup -room bwjtXvJw1zI4KFT2 -from 2026-09-01 -to 2026-10-01
./meeks lookup -ip 198.51.100.7
```

`-room` 指定時は、そのルームに参加したピアの TURN 利用記録（`turn_auth`）も併せて出力します。

> メッセージ本文はサーバーを通らない（P2P）か、暗号化された状態でしか通らないため、運営者は「どの発言を誰がしたか」を特定できません。記録できるのは「いつ・どの IP から・どのルームに接続したか」です。保存項目や期間の法的な十分性は、弁護士等の専門家に確認してください。

## セキュリティ上の注意・制約

- 参加には既存の参加者の承認が必要です。承認されると暗号鍵と過去ログを受け取れます。
- サーバーに保管するのは、ルーム ID のハッシュ、受付用の公開鍵、申込者の表示名と公開鍵、暗号化された承認前メッセージ、申込者宛てに暗号化された鍵だけです。申込者が鍵を受け取ると、その申し込みとメッセージは削除されます。運営者は通信や保管データから内容を読めません。
- **想定している運営者の攻撃は「見知らぬ名前での申し込み」です**。参加者が拒否すれば入れません。次の2つは想定の対象外です。確認コードを電話などで照合すれば、これらも見破れます。
  - 運営者が、参加予定の人の名前を名乗って申し込むこと
  - 運営者が、本物の申し込みの公開鍵をすり替えて割り込むこと
- サーバーは参加者と申込者を区別できません（鍵を見られないため）。URL を知る第三者が、保留中の申し込みを拒否することはできます。
- 申し込みは 7 日、拒否は 24 時間で自動削除されます。拒否された人は 24 時間申し込めません。
- TURN 中継は Meeks のルームに接続している間だけ使える（認証情報に紐づく WebSocket が切れると新規の中継・許可・更新を拒否し、既存の中継も最長 5 分程度で止まる）。同時中継数は 1 人あたり・全体で上限あり。中継先としてプライベート／ループバックアドレスは拒否する
- ルーム鍵は固定で、前方秘匿性（Forward Secrecy）はありません。参加者ごとの本人認証もないため、表示名は自己申告です。
- サイドバーの「安全確認コード」が全員で一致すれば、同じ鍵を使っています。
- Web 配信型 E2EE の原理的な制約として、配信する JavaScript をサーバーが改ざんした場合は保護できません。
- ビデオ通話はメッシュ接続のため、実用的な人数は 4〜6 人程度です。
- サーバーが知り得るメタデータ: ルーム ID、接続時刻と IP、参加人数、中継したデータの量とタイミング。

## 開発

```bash
go test ./...
```

デバッグ用 URL パラメータ: `?transport=turn`（TURN 中継を強制）、`?transport=relay`（チャット・ファイルを WebSocket 中継に強制）。
例: `/{ルームID}?transport=relay`

```
main.go                      エントリポイント（serve / lookup）
internal/signaling/          WebSocket マッチング・中継
internal/turnserver/         内蔵 STUN/TURN
internal/iplog/              IP ログの記録・自動削除・検索
internal/store/              ルームの存在と参加申し込みの保管
web/static/                  ブラウザクライアント（埋め込み）
  crypto.js                  E2EE（AES-256-GCM）・鍵の受け渡し（ECDH）
  room.js                    WebRTC・フォールバック・過去ログ・ファイル・通話
```

## ライセンス

[MIT License](LICENSE) (C) PAPS
