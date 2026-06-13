# TanLabs API

Auth API on Cloudflare Workers (Hono + D1 + KV).

## Dev

```bash
pnpm install
pnpm dev
```

- API: http://localhost:8787
- Swagger: http://localhost:8787/
- Seed users: `user@example.com` / `admin@example.com` — password `Password123!`

## Deploy

```bash
pnpm deploy
```

Production config: `wrangler.jsonc` → `env.production` (KV id, CORS origins, secrets via `wrangler secret put --env production`).
