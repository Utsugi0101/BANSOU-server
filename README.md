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

## Secrets

```sh
wrangler secret put ATTEST_PRIVATE_JWK
```

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

## GitHub Actions で検証する際の情報

- ISSUER: `https://attest.example.com`
- JWKS URL: `https://attest.example.com/.well-known/jwks.json`

## エンドポイント

- `GET /.well-known/jwks.json`
- `GET /policy`
- `POST /attestations/issue`

## 環境変数

- `ISSUER` (例: `https://attest.example.com`)
- `ATTEST_PUBLIC_JWK` (公開鍵 JWK)
- `ATTEST_PRIVATE_JWK` (秘密鍵 JWK / secret)
- `POLICY_JSON` (任意)
