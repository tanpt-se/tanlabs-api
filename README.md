# TanLabs API

Cloudflare Workers auth API ported from [auth-lab](https://github.com/tanpt-se/auth-lab), using **Hono + D1 + KV**.

## Stack

- **Runtime:** Cloudflare Workers
- **Framework:** Hono
- **Database:** D1 (SQLite)
- **Ephemeral state:** KV + D1 `auth_ephemeral_state`
- **Password hashing:** Web Crypto PBKDF2-SHA256

## Quick start

```bash
pnpm install
pnpm dev          # applies migrations, seeds roles/users, starts wrangler dev
```

Default seeded users (override via env in `scripts/seed-auth.ts`):

| Email | Password |
|-------|----------|
| `user@example.com` | `Password123!` |
| `admin@example.com` | `Password123!` |

## API endpoints (27 routes)

Compatible with auth-lab web-app/admin clients.

- `POST /auth/login`, `/auth/refresh`, `/auth/internal/refresh`, `/auth/logout`
- `POST /auth/register`, email verification, forgot/reset/account-setup
- `GET /auth/oauth/:provider/start`, `/auth/oauth/:provider/callback`
- `GET|POST /auth/2fa/*`
- `GET|POST|DELETE /users/me/*`
- `GET|DELETE /auth/sessions/*`
- `GET /health/live`, `/health/ready`

## Connect auth-lab frontend

Point API URL to this worker (e.g. `http://localhost:8787` in dev):

```env
NEXT_PUBLIC_API_URL=http://localhost:8787
```

CORS origins are configured in `wrangler.jsonc` (`CORS_ALLOWED_ORIGINS`).

## Production secrets

Set via `wrangler secret put`:

- `ACCESS_TOKEN_SECRET`, `TOKEN_HASH_SECRET`, `ACCESS_ONLY_REFRESH_SECRET`
- `TWO_FACTOR_SECRET_ENCRYPTION_KEY`
- `GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET`, `GOOGLE_OAUTH_REDIRECT_URI`
- `EMAIL_API_KEY` (optional, for Resend)

Create a real KV namespace and update `AUTH_KV` id in `wrangler.jsonc`.
