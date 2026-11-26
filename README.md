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
- **Logout**: RP-initiated logout from a flow of the history, its id_token as `id_token_hint`
- **Locked mode**: for an instance several people share, see [Locked mode](#locked-mode)

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
| `OIDC_JWKS_URI` | JWKS URI (overrides discovery) |
| `OIDC_END_SESSION_URL` | End session endpoint, for the logout (overrides discovery) |
| `OIDC_POST_LOGOUT_REDIRECT_URI` | Where the provider sends the browser back after the logout, with `state` (optional) |
| `LOCKED` | `true` for a shared deployment, see [Locked mode](#locked-mode) (default: `false`) |
| `SESSION_TTL` | Locked mode: how long a browser's session, with its history, outlives its last request (default: `12h`) |

## Locked mode

By default the client trusts whoever opens it: one configuration and one history for everyone, the client secret shown in the Config tab, and requests sent to any URL typed in a form. That suits a local instance. For an instance several people share, registered at the provider like a real client, set `LOCKED=true`:

- **The provider and the client are fixed.** The endpoints, the client ID and secret and the redirect URIs come from the `OIDC_*` variables only: the config file is neither read nor written, and discovery shows the provider's document without updating anything. `POST /api/config` is refused (403) when it changes one of them, and the URLs and client credentials in the body of the other requests are ignored: the server only calls the configured endpoints. Set every endpoint you need, as none comes from discovery.
- **The secret stays on the server.** `/api/config` leaves it out.
- **One session per browser**, named by a random cookie (`HttpOnly`, `Secure`, `SameSite=Lax`). It holds the history, the pending `state`s and the settings a tester tunes in the Config tab: scopes, response type and mode, PKCE, extra parameters. A callback is only accepted with a `state` its own session started, and the logout only uses the session's flows. Sessions live in memory: they are dropped `SESSION_TTL` after their last request, and on restart.
- **Security headers**: `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, and `Cache-Control: no-store` on `/api/*` and `/auth/*`.

The cookie is `Secure`, so serve the client over HTTPS (browsers also accept it on `http://localhost`). Locked mode does not decide who may open the page: put the client behind a reverse proxy that does.

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

## Logout

In the History tab, **Logout →** sends the browser to the end session endpoint with the flow's `id_token` as `id_token_hint` (OpenID Connect RP-Initiated Logout). With a post logout redirect URI configured, and registered at the provider, it adds `post_logout_redirect_uri` and a `state`, kept on the flow; set it to the client's root to land back on the History tab, which checks the `state` that comes back against it:

```
http://<host>:<port>/
```

`POST /auth/logout` with a `flow=<id>` form field does the same for a flow of the history, or, without `flow`, for the newest one that has an `id_token`. It refuses requests from another site (`Sec-Fetch-Site`, or `Origin` for browsers without it).

