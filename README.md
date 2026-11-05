# IT Desk — Chattanooga plants

Página do IT Desk publicada no Cloudflare (Worker + D1). Login pelo Cloudflare Access (conta Google ou código por e-mail); o worker confere o token do Access em toda requisição.

- `public/index.html` — a página (a mesma `Open-Items.html` do PC; no site ela grava na API).
- `src/worker.js` — verifica o login do Access e expõe `GET/PUT /api/data` (página), `GET /api/me` e `POST /api/sync` (script do PC: service token do Access + `X-Sync-Key`).
- `wrangler.toml` — configuração (binding `DB` = D1 `itdesk`; variáveis `TEAM_DOMAIN`, `ACCESS_AUD`; secret `SYNC_KEY`).

Cada `git push` na branch `main` publica automaticamente (Cloudflare Workers Builds).
Os dados não ficam no repositório: ficam no D1. O `cloud-config.json` (chaves) fica só no PC.
