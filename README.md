# oidc-test-client

A browser-based debugger for OIDC providers and OAuth2 authorization servers.

## Features

- **Config**: Set provider URLs, client credentials, scopes
- **Discovery**: Fetch and inspect `/.well-known/openid-configuration`
- **Authorize**: Build authorization URLs with full parameter control + PKCE (S256/plain)
- **Token Exchange**: Exchange authorization codes for tokens
- **Token Refresh**: Refresh access tokens
- **UserInfo**: Call the userinfo endpoint
- **Introspect**: Token introspection
- **JWT Decode**: Inspect JWT header/payload/claims (no signature verification)
- **Full Flow**: Complete browser-redirected auth code flow

All operations show the raw HTTP request and response for easy debugging.

## Quick Start

### Docker Compose

```bash
docker compose up
```

Then open http://localhost:8080.

### Local (requires Go 1.22+)

```bash
go run ./cmd/
```

## Configuration

Settings are saved to `config.json` in the working directory and persist across restarts.

### Environment Variables

| Variable | Description |
|---|---|
| `PORT` | Listen port (default: `8080`) |
| `CONFIG_FILE` | Path to config JSON (default: `config.json`) |
| `OIDC_ISSUER_URL` | Provider issuer URL |
| `OIDC_CLIENT_ID` | Client ID |
| `OIDC_CLIENT_SECRET` | Client secret |
| `OIDC_REDIRECT_URI` | Redirect URI |
| `OIDC_AUTH_URL` | Authorization endpoint (overrides discovery) |
| `OIDC_TOKEN_URL` | Token endpoint (overrides discovery) |
| `OIDC_USERINFO_URL` | UserInfo endpoint (overrides discovery) |
| `OIDC_INTROSPECTION_URL` | Introspection endpoint (overrides discovery) |

## Startup Script

Mount a shell script at `/startup.sh` (or set `STARTUP_SCRIPT`) to run setup logic before the app starts. The script is **sourced**, so environment variables it sets propagate to the app:

```bash
# my-startup.sh — register a dynamic client and export credentials
RESP=$(curl -s -X POST "$OIDC_ISSUER_URL/connect/register" \
  -H "Content-Type: application/json" \
  -d '{"client_name":"test","redirect_uris":["http://localhost:8080/auth/callback"]}')

export OIDC_CLIENT_ID=$(echo "$RESP" | jq -r .client_id)
export OIDC_CLIENT_SECRET=$(echo "$RESP" | jq -r .client_secret)
```

Mount it in `docker-compose.yml`:

```yaml
services:
  oidc-test-client:
    volumes:
      - ./my-startup.sh:/startup.sh:ro
    environment:
      OIDC_ISSUER_URL: https://accounts.example.com
```

## Auth Callback

For the Full Flow tab, set your redirect URI to:

```
http://<host>:<port>/auth/callback
```

The callback endpoint exchanges the authorization code for tokens and displays the result.
