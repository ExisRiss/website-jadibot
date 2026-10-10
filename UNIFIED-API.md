# Jadibot Unified API

Production base URL:

```text
https://website-jadibot-by-alzriss.vercel.app/api/v1
```

The Jadibot website, platform Auth/database operations, bot gateway, and the former AlzRiss API now share the Jadibot domain. The database is never exposed as unrestricted SQL; `/database/*` is a scoped, authenticated, read-only data API.

## Public

- `GET /api/v1` or `/api/v1/health` — service health.
- `POST /api/v1/auth/username-login` — AlzRiss API username login.
- `GET|POST /api/v1/gateway/{endpoint}` — API-key gateway.
- `GET /s/{id}` — short URL redirect.

## Authenticated user

Pass a Supabase access token as `Authorization: Bearer <token>`.

- `GET|POST|PATCH|DELETE /api/v1/keys`
- `POST /api/v1/premium`
- `POST /api/v1/plugins` — multipart plugin upload.
- `POST /api/v1/chat/upload` — multipart chat attachment upload.
- `GET /api/v1/database/profile`
- `GET /api/v1/database/roles`
- `GET /api/v1/database/endpoints`
- `GET /api/v1/database/keys`
- `GET /api/v1/database/plans`
- `GET /api/v1/database/payments`
- `GET /api/v1/database/plugins`
- `GET /api/v1/database/notifications`
- `GET /api/v1/database/announcements`
- `GET /api/v1/database/status`

## Staff and Owner

- `GET /api/v1/database/profiles` — Admin/Owner.
- `GET /api/v1/owner?action=vapikeys` — Admin/Owner.
- `POST /api/v1/owner?action=vapikeys` — Owner.
- `POST /api/v1/owner?action=settings` — Owner.
- `PATCH /api/v1/owner?action=user` — Admin/Owner with immutable primary Owner protection.

## Existing Jadibot platform and bot endpoints

Existing website endpoints remain compatible:

- `/api/platform/*` — website Auth, profiles, global chat, plugins, media, audit, and account administration.
- Existing `/api/session/*`, `/api/settings/*`, `/api/backup/*`, and bot routes continue under the Jadibot website domain.

## Compatibility

These aliases are supported:

```text
/api/alzriss/*
/api/auth/username-login
/api/keys
/api/owner
/api/plugins
/api/chat/upload
/api/premium
/api/gateway/*
```

`https://alzriss-api.vercel.app/*` permanently redirects to the corresponding Jadibot URL. HTTP 308 is used so methods, request bodies, and authorization headers remain compatible.

## Gateway example

```bash
curl -H "X-API-Key: alzriss_..." \
  "https://website-jadibot-by-alzriss.vercel.app/api/v1/gateway/tools/qrcode?text=Hello"
```

## Security

- Service-role credentials remain server-side.
- Database resources use an explicit allowlist.
- User-owned rows are filtered by authenticated user ID.
- Staff/Owner routes enforce API roles.
- Primary Owner identity cannot be modified.
- Gateway keys are stored as SHA-256 hashes.
- CORS and preflight support are enabled for public API clients.
