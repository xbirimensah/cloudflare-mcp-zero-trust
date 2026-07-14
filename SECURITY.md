# Security policy

## Supported version

Security fixes target the latest release on `main`.

## Reporting

Use the private repository's security-reporting channel. Do not include API
tokens, Access assertions, email identities, or production configuration in an
issue, test, screenshot, or log.

## Boundary assumptions

This package is one layer, not the whole deployment:

- the origin listens on loopback or an equivalently restricted interface;
- Cloudflare Tunnel is the only route to the public hostname;
- an operator creates the Access application and exact-email policy first;
- API tokens are short-lived or rotated and minimally scoped;
- the origin environment is private and is not committed to source control;
- HTTPS and identity-provider security remain Cloudflare/operator concerns.

The middleware treats requests for the configured public host, requests carrying
Cloudflare forwarding headers, and requests carrying an Access assertion as
untrusted until a single assertion is fully verified. Local loopback requests
without those signals remain available for liveness probes and administration.

## Deliberate non-features

The CLI does not create Access policies, tunnels, DNS, service tokens, API
tokens, or OAuth client secrets. This avoids turning a narrow reconciliation
tool into an account-wide control plane.
