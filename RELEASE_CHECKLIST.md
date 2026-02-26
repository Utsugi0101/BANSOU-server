# BANSOU-server Release Checklist

## Preflight

- [ ] `npm ci`
- [ ] `npm run typecheck`
- [ ] `wrangler.toml` の `ISSUER` が公開ドメインと一致
- [ ] `ATTEST_DB` binding の `database_id` が正しい

## Secrets / Vars

- [ ] `ATTEST_PRIVATE_JWK` (secret)
- [ ] `GATE_API_TOKEN` (secret)
- [ ] `OPENAI_API_KEY` (optional secret)
- [ ] `CLOUDFLARE_API_TOKEN` (GitHub secret)
- [ ] `CLOUDFLARE_ACCOUNT_ID` (GitHub secret)

## Release

- [ ] `.github/workflows/deploy-worker.yml` を手動実行 or main push
- [ ] `GET /gate/health` が `ok: true`
- [ ] `POST /gate/evaluate` が 200/401 を正しく返す

## Post-release

- [ ] `BANSOU-test` から `npm run e2e:check` が通る
- [ ] Action から gate mode が通る
