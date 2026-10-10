# Dynamic bot API configuration

The website proxy reads its backend origin from this public, non-secret Gist:

```text
https://gist.githubusercontent.com/ExisRiss/a35c7a45c4acf1d542aa328c2b692715/raw/umi-server-config.json
```

Edit the Gist file `umi-server-config.json` whenever the bot API moves. Update only:

- `botApiOrigin` — valid HTTPS origin for the bot API, e.g. `https://api.example.com`;
- `version` — a changed timestamp/revision string;
- optionally `refreshSeconds` between 15 and 300.

The website must use the **stable URL above**, without GitHub's revision hash in the path. A URL containing a revision hash does not automatically follow future edits.

Never add panel URLs, raw Pterodactyl allocation IPs, API keys, tokens, credentials, WhatsApp session files, phone numbers, or pairing codes to this Gist.
