# Deploy website Jadibot securely

The frontend calls its own `/api/*` routes. `api/proxy.js` then relays authorized requests to the bot API configured by `UMI_API_ORIGIN`.

## Required production setting

Set this **server-side Vercel environment variable** for Production, Preview, and Development as appropriate:

```text
UMI_API_ORIGIN=https://api.example.com
```

The value must be an HTTPS origin only—no path, query string, username/password, raw Pterodactyl allocation, or `http://` URL.

### Why an HTTPS origin is required

The proxy relays an authenticated Supabase bearer token to the bot API. A raw Pterodactyl allocation commonly serves plain HTTP and must not receive that token across an unencrypted network link. Put a valid TLS reverse proxy/domain in front of the bot API first, then set `UMI_API_ORIGIN` to that public HTTPS origin.

The bot API should be reachable at:

```text
GET https://api.example.com/api/health
```

## Vercel deployment checklist

1. Add the environment variable in **Vercel → Project → Settings → Environment Variables**. Do not put it in browser JavaScript.
2. Link the HTTPS domain/reverse proxy to the current Pterodactyl bot allocation.
3. Deploy the repository to Vercel.
4. Verify:

```bash
curl -fsS https://YOUR_WEBSITE/api/health
```

A successful response is proxied from `https://api.example.com/api/health` and contains `ok: true`.

## Local validation

```bash
cp .env.example .env.local
# Replace the example origin with a non-production HTTPS test origin.
npm ci
node --check api/proxy.js
```

Do not commit `.env.local`, Vercel tokens, GitHub tokens, WhatsApp session files, or pairing codes.
