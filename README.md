# BANSOU-server

Cloudflare Workers + Hono で動く最小の中央署名サーバです。VSCode拡張からのリクエストに対して署名付きJWTを発行し、JWKSを公開します。

## セットアップ

```sh
npm install
```

### 鍵生成

```sh
node scripts/gen-keys.mjs
```

出力された `ATTEST_PUBLIC_JWK` と `ATTEST_PRIVATE_JWK` を使います。

## ローカル実行

`wrangler.toml` を編集して `ISSUER` と `ATTEST_PUBLIC_JWK` を設定します。

```sh
wrangler secret put ATTEST_PRIVATE_JWK
wrangler dev
```

## デプロイ

```sh
wrangler deploy
```

GitHub Actions からは `.github/workflows/deploy-worker.yml` を使ってデプロイできます。
必要な Secrets:

- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`

## Secrets

```sh
wrangler secret put ATTEST_PRIVATE_JWK
wrangler secret put GATE_API_TOKEN
```

## D1 (ledger mode)

PRにJWTをコミットしない運用では、サーバーに証明を保存するためにD1を使います。

1. D1 DBを作成
```sh
wrangler d1 create bansou-attest
```

2. `wrangler.toml` に `d1_databases` バインドを追加（`binding = "ATTEST_DB"`）

3. `quiz/submit` 成功時に ledger に保存され、`gate/evaluate` で照会できます。

## 動作確認

### JWKS

```sh
curl http://localhost:8787/.well-known/jwks.json
```

### Attestation 発行

```sh
curl -X POST http://localhost:8787/attestations/issue \
  -H 'Content-Type: application/json' \
  -d '{
    "sub": "github_login",
    "repo": "owner/name",
    "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "artifact": { "path": "src/foo.ts", "rangeStart": 10, "rangeEnd": 40 },
    "quiz_id": "core-pr",
    "quiz_version": "1.0.0",
    "score": 90,
    "duration_ms": 22000,
    "questions_hash": "sha256:...",
    "answers_hash": "sha256:..."
  }'
```

### クイズ生成 (server-side)

```sh
curl -X POST http://localhost:8787/quiz/generate \
  -H 'Content-Type: application/json' \
  -d '{
    "sub": "github_login",
    "repo": "owner/name",
    "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "quiz_id": "core-pr",
    "quiz_version": "1.0.0",
    "files": ["src/foo.ts"],
    "diffsByFile": {
      "src/foo.ts": "diff --git a/src/foo.ts b/src/foo.ts\n@@ -1,2 +1,2 @@\n-const a = 1\n+const a = 2"
    }
  }'
```

### クイズ提出 (server-side採点 + JWT発行)

```sh
curl -X POST http://localhost:8787/quiz/submit \
  -H 'Content-Type: application/json' \
  -d '{
    "quiz_session_token": "<from /quiz/generate>",
    "answers": [0]
  }'
```

### gate health (デプロイ診断)

```sh
curl http://localhost:8787/gate/health
```

本番でも `GET /gate/health` を叩くと、`ATTEST_DB` バインドと schema 初期化可否を確認できます。

## GitHub Actions で検証する際の情報

- ISSUER: `https://attest.example.com`
- JWKS URL: `https://attest.example.com/.well-known/jwks.json`

## エンドポイント

- `GET /.well-known/jwks.json`
- `GET /policy`
- `POST /quiz/generate`
- `POST /quiz/submit`
- `POST /gate/evaluate`
- `GET /gate/health`
- `POST /attestations/issue`

## 環境変数

- `ISSUER` (例: `https://attest.example.com`)
- `ATTEST_PUBLIC_JWK` (公開鍵 JWK)
- `ATTEST_PRIVATE_JWK` (秘密鍵 JWK / secret)
- `OPENAI_API_KEY` (任意。設定時はOpenAIでクイズ生成、未設定時はテンプレクイズ)
- `ATTEST_DB` (D1 binding。ledger modeで必須)
- `GATE_API_TOKEN` (任意。`/gate/evaluate` のBearer token)
- `POLICY_JSON` (任意)
