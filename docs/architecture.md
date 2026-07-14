# Architecture

```text
MCP client
    |
    | OAuth discovery + dynamic registration + browser sign-in
    v
Cloudflare Access / Managed OAuth
    |
    | Cf-Access-Jwt-Assertion
    v
Cloudflare Tunnel --> loopback origin --> AccessJWTMiddleware --> FastMCP tools
```

The provisioning and request paths deliberately share no credentials:

- `ManagedOAuthClient` receives a Cloudflare API token only for an explicit
  plan/apply operator session.
- `AccessJWTVerifier` receives only public JWKS data and origin trust settings.
- FastMCP tools receive a request only after the origin assertion is verified.

The CLI mutates exactly one application addressed by account and application
ID. Before a write, it validates ID, type, exact domain, exact-email policies,
and each new redirect URI. The update is a deep copy of the current application,
so unrelated settings are preserved.

