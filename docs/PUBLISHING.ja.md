# 公開前チェックリスト（agent-doorman v0.1.0）

GitHubとnpmに公開する前に確認する事項をまとめます。作成時点は2026年10月5日です。

## 1. 検証済みの項目

| 項目 | 結果 |
|---|---|
| 単体・相互運用・E2Eテスト | 91件すべて合格（Node.js 20、22、24） |
| Web Bot Authドラフトのテストベクトル（付録C.2） | 3件とも検証に合格。署名側は公開された署名値をバイト単位で再現 |
| 型チェック | エラーなし |
| 公開用パッケージ（`npm pack`） | 約54KB。実行時の依存パッケージなし |
| パッケージ単体での動作 | 新しいプロジェクトにtarballを入れて確認（24項目合格）。`node:http` とExpressの例は実際のHTTPで、Workerの例はworkerd（Miniflare）上で動作を確認。Workerのバンドルに `node:` の読み込みが含まれないこと、TypeScriptの型解決（NodeNext、Bundler）も確認 |
| GitHub Action | `run` の処理をローカルで実行。点数・判定の出力と、点数不足時の終了コード2の伝播を確認 |
| HTMLレポート | デスクトップ、スマートフォン幅、ダークモードの表示を確認 |

同じ確認はCIでも実行します（`.github/workflows/ci.yml` の test、package、demo の3ジョブ）。手元では `scripts/ci/package-smoke.sh` で再現できます。

## 2. 未検証の項目

- Next.jsの実アプリ（Edge runtime）での動作。Workerと同じFetch APIの経路を使いますが、実行はしていません。
- 実在のエージェントが付けた署名との疎通。相互運用性はテストベクトルで確認しています。
- 実際のCDNやロードバランサーの配下での `trustProxy`。デモでは `X-Forwarded-Host` 経由の署名検証を確認しています。
- WindowsとmacOSでのCLI。
- GitHub上でのCI。ワークフローは作成済みですが、まだ実行していません。

## 3. 公開手順

### 3-1. 仮の値を置き換える

リポジトリには `__OWNER__`（GitHubのユーザー名または組織名）、`__AUTHOR__`（作者名）、`__SECURITY_EMAIL__`（脆弱性報告の連絡先）が残っています。次の1コマンドで置き換えます。

```sh
node scripts/set-owner.mjs <GitHubユーザー名> "<作者名>" <連絡先メールアドレス>
npm run check:placeholders   # 「No placeholders left.」と表示されれば完了
```

置き換え対象は `package.json`、`src/version.ts`、README、`SKILL.md`、`action.yml`、`NOTICE`、`SECURITY.md` です。`npm publish` の直前にも同じ確認が自動で走るため、置き換え漏れがあると公開は止まります。

### 3-2. 名前を確保する

```sh
npm view agent-doorman   # 404 なら未使用（10月5日時点では未使用）
```

続けて、GitHubに `agent-doorman` リポジトリを作成します。

### 3-3. 初回コミットとCI

```sh
git init && git add -A && git commit -m "agent-doorman 0.1.0"
git branch -M main
git remote add origin git@github.com:<owner>/agent-doorman.git
git push -u origin main
```

CIの3ジョブが通ることを確認します。ワークフローは `actions/checkout@v4` と `actions/setup-node@v4` を使っています。組織の方針があれば、最新版またはコミットSHAに固定してください。

### 3-4. GitHub側の設定

- 「Settings」の「Security」で「Private vulnerability reporting」を有効にします（`SECURITY.md` がこの窓口を案内しています）。
- Topics に `ai-agents`、`web-bot-auth`、`http-message-signatures`、`bot-management`、`agentic-commerce` を設定します。
- ソーシャルプレビュー画像には `docs/images/door-report.png` を使えます。

### 3-5. npmへの公開

1. npmアカウントで2要素認証を有効にし、Automation token をリポジトリのSecretsに `NPM_TOKEN` として登録します。
2. npm公開を別途行う場合だけ、Actionsの `publish` ワークフローを手動実行します。GitHubリリース作成ではnpm公開処理は走りません。
3. 手動で公開する場合は `npm publish --access public` を実行します。型チェック、ビルド、テスト、仮の値の確認が先に走ります。

### 3-6. GitHub Actionとして使えるようにする

`v0.1.0` に加えて `v0` タグを付けると、利用者は `uses: <owner>/agent-doorman@v0` と書けます。`action.yml` はnpmに公開した版を `npx` で実行するため、npmへの公開後に動作します。Marketplaceへの掲載は任意です。

## 4. 公開前に判断が必要な点

- **ライセンス**：特許条項のあるApache-2.0にしています。MITにする場合は `LICENSE` と `package.json` を変更してください。
- **`/.well-known/agent-policy.json` の書式**：このプロジェクトが提案する試験的な書式で、標準ではありません。READMEと `docs/agent-policy.md` にもその旨を書いています。名前やパスを変えるなら、利用者が出る前の公開前に決めるのが望ましいです。
- **既知エージェントの一覧**（`src/gate/agents.ts`）：公開前に各社の公開資料と照合してください。検索エンジンのクローラーは、検索の掲載を誤って止めないよう意図的に除外しています。
- **能動モードの扱い**：AIエージェントを名乗るリクエストと偽の署名を送ります。CLIは実行時に警告を表示し、READMEと `SKILL.md` にも自分のサイト限定と明記しています。
- **テストベクトルのライセンス表示**：テストで使うベクトルと鍵はIETF文書から取ったもので、IETF Trustの規定に従い、Revised BSD Licenseの表示を `test/fixtures/IETF-LICENSE.txt` に置きました。npmパッケージには含まれません。これは規定を読んだうえでの対応で、法的な判断ではありません。
- **特許**：前回の調査で挙げた中国の「実行前チェック」系の出願は、エージェント側の行動制御を対象としています。本ツールはサイト側の署名検証と入口でのポリシー適用で、構成は異なると考えられます。中国で商用展開する場合は、弁理士に確認してください。

## 5. ローンチ計画（案）

- 時期：年末商戦の前が適しています。2026年のブラックフライデーは11月27日なので、11月上旬までの公開を目安にします。
- 伝える内容：「GPTBotと名乗れば誰でも通れる規則になっていないか、1コマンドで確認できる」。
- 素材：`docs/images/door-report.png`、`npm run demo` の32点と100点の比較、ターミナル出力の録画。
- 投稿先：Hacker News（Show HN）、Reddit（r/webdev、r/node）、X、dev.to。日本語ではZennとQiita。
- 避けること：他社のサイトに能動モードを実行した結果を公開しないでください。受動モードの結果でも、特定企業を名指しした比較は避けるのが無難です。
- 最初のgood first issue候補：既知エージェントの追加、Redis向けのレート制限ストア、Next.jsの例のCI化。

## 6. 次の版の候補

- 鍵ディレクトリの応答に付く署名の検証
- Redis、Durable Objects向けのレート制限ストアとnonceストア
- 監査でのJavaScript描画（Playwrightを任意の依存として追加）
- Next.jsの例のCI化と、Fastify、Honoのアダプター
- nonceが再利用されたときに、ドラフト4.3節に沿って429と `Accept-Signature` で新しい署名を求める処理
