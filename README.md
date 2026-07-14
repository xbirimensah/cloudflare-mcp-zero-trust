# Cloudflare MCP Zero Trust

A small, vendor-neutral Python boundary for publishing an MCP server through a
pre-existing Cloudflare Access application. It keeps ordinary MCP client setup
simple: the user enters the MCP URL, the client dynamically registers, and the
user signs in through Cloudflare Access. There is no static OAuth client ID or
client secret to copy into every client.

The framework does two narrowly separated jobs:

1. `cf-mcp-zero-trust plan/apply` validates one existing self-hosted Access
   application and enables Cloudflare Managed OAuth dynamic client registration.
2. `AccessJWTMiddleware` verifies Cloudflare's signed assertion again at the
   private origin before an MCP request reaches any tool.

It does **not** create tunnels, DNS records, Access applications, or identity
policies. Those resources stay explicit and operator-owned.

## Security model

- only exact-email `allow` policies are accepted;
- `bypass`, `everyone`, and whole-domain rules fail validation;
- the Access application must exactly match the requested public DNS host;
- client callbacks must be explicit HTTPS URLs (an optional final `/*` is the
  only accepted wildcard form);
- existing application fields, policies, and callbacks are preserved;
- the origin verifies RS256 signature, issuer, audience, time claims, token
  type, subject, and exact email identity;
- loopback traffic remains available for local administration, but the public
  host, Cloudflare forwarding headers, or any Access assertion activates the
  fail-closed boundary;
- tokens, audience tags, and email identities never appear in plan output or
  object representations.

Cloudflare still terminates the public TLS connection, so keep the origin bound
to loopback or otherwise unreachable except through your tunnel.

## Install

```bash
uv add cloudflare-mcp-zero-trust
```

For this repository:

```bash
uv sync --extra dev --locked
```

## 1. Plan, then enable Managed OAuth

Create a scoped Cloudflare API token with only the permissions needed to read
and update the one Access application. Export it only in the current shell:

```bash
export CLOUDFLARE_API_TOKEN='runtime-only-token'
export CLOUDFLARE_ACCOUNT_ID='your-account-id'
export CLOUDFLARE_ACCESS_APPLICATION_ID='your-application-id'

uv run cf-mcp-zero-trust plan --host mcp.example.com
```

`plan` is read-only and redacted. Apply explicit browser-client callbacks when
needed:

```bash
uv run cf-mcp-zero-trust apply \
  --host mcp.example.com \
  --redirect-uri https://claude.ai/api/mcp/auth_callback
```

The command is idempotent. It enables localhost and loopback dynamic callbacks
for CLI agents, preserves all existing HTTPS callbacks, and adds only the URLs
you explicitly provide.

## 2. Protect the origin

Set the origin-only trust values outside the repository:

```bash
export CF_MCP_TEAM_DOMAIN='https://your-team.cloudflareaccess.com'
export CF_MCP_ACCESS_AUDIENCE='your-access-audience-tag'
export CF_MCP_ALLOWED_EMAILS='first@example.com,second@example.com'
export CF_MCP_PUBLIC_HOST='mcp.example.com'
```

See [`examples/server.py`](examples/server.py) for a complete FastMCP example.
The essential wiring is:

```python
import os
from starlette.middleware import Middleware
from cloudflare_mcp_zero_trust import (
    AccessJWTMiddleware,
    AccessJWTVerifier,
    ManagedOAuthSettings,
)

settings = ManagedOAuthSettings.from_environ(os.environ)
if settings is None:
    raise RuntimeError("Origin trust settings are required")

middleware = [
    Middleware(AccessJWTMiddleware, verifier=AccessJWTVerifier(settings))
]
```

Pass that list to FastMCP's `http_app(...)` or `run(...)` call. Bind the origin
to `127.0.0.1`, use Streamable HTTP, and expose it only through the tunnel.

## 3. Connect an MCP client

Add only the public URL, for example `https://mcp.example.com/mcp`. A compatible
client discovers OAuth metadata, dynamically registers, and opens Cloudflare's
sign-in flow. Static OAuth credentials are not part of this framework.

## Commands

```text
cf-mcp-zero-trust plan  --host HOST
cf-mcp-zero-trust apply --host HOST [--redirect-uri HTTPS_URL ...]
```

Both commands refuse incomplete environment settings and unsafe application
policies. `apply` is the only command that writes to Cloudflare.

## Development

```bash
uv run pytest --cov=cloudflare_mcp_zero_trust --cov-fail-under=80
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run pip-audit
uv build
```

See [SECURITY.md](SECURITY.md) before adapting the boundary.
