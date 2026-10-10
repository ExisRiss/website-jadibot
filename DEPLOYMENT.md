# Deploy website Jadibot securely

The frontend calls its own `/api/*` routes. `api/proxy.js` relays authorized requests to the bot API. The bot API origin can be changed dynamically through a GitHub Gist without editing/redeploying the website.

## Important boundary: bot API, not Pterodactyl panel

The website must route to the **bot API origin**, not the Pterodactyl panel URL or a Pterodactyl Client API token.

- Correct config value: `https://api.example.com` — this must serve `/api/health` from the bot.
- Incorrect config value: a Pterodactyl panel URL, raw allocation IP/port, token, session, or pairing code.

The website forwards authenticated user requests. Never send its bearer token through a raw `http://` Pterodactyl allocation. Put a valid TLS reverse proxy/domain in front of the bot API first.

## Dynamic GitHub Gist config

Create a **public** Gist with one file named `umi-server-config.json`, using `umi-server-config.example.json` as the template:

```json
{
  "schemaVersion": 1,
  "version": "2026-10-10T00:00:00Z",
  "refreshSeconds": 60,
  "botApiOrigin": "https://api.example.com"
}
```

The Gist is a public routing configuration only. Do **not** put any token, Pterodactyl credential, WhatsApp number, session data, pairing code, or password in it.

Each warm Vercel function refreshes the Gist configuration at the configured interval (15–300 seconds; default 60). It retains the last valid configuration for up to 15 minutes if GitHub is temporarily unavailable.

### Required Vercel setting

Set this server-side Vercel environment variable for Production, Preview, and Development:

```text
UMI_CONFIG_GIST_URL=https://gist.githubusercontent.com/OWNER/GIST_ID/raw/umi-server-config.json
```

Use the raw URL for the specific Gist file. The Gist URL itself is not a credential.

Optional static fallback when no Gist is configured:

```text
UMI_API_ORIGIN=https://api.example.com
```

Both direct and Gist-provided origins are validated as HTTPS origins without paths, credentials, queries, or fragments.

## Update flow after a server/IP migration

1. Move the bot API behind a new valid HTTPS origin.
2. Confirm `GET https://NEW_ORIGIN/api/health` returns `ok: true`.
3. Edit only `botApiOrigin` and `version` in `umi-server-config.json` on GitHub Gist.
4. Wait up to `refreshSeconds` for warm functions; a new Vercel invocation picks up the change immediately.
5. Confirm `https://YOUR_WEBSITE/api/health` returns the target health response. The response includes `X-Umi-Config-Version` for non-secret diagnostics.

## Local validation

```bash
cp .env.example .env.local
# Set UMI_CONFIG_GIST_URL to a test public Gist raw URL, or use a test HTTPS UMI_API_ORIGIN.
npm ci
node --check api/_bot-config.js
node --check api/proxy.js
```

Do not commit `.env.local`, Vercel tokens, GitHub tokens, WhatsApp session files, or pairing codes.
