# TDD checkpoint: Zero Trust foundation

## RED

The initial tests describe the security boundary before implementation:

- origin JWT verification must fail closed for Cloudflare-forwarded traffic;
- only exact-email Access policies are accepted;
- Managed OAuth changes preserve the existing Access application;
- dynamic client redirects must be explicit HTTPS endpoints;
- plan and CLI output must not reveal identities, audiences, or API tokens.

Expected RED result: test collection fails because `auth`, `cloudflare_api`, and
`cli` do not exist yet.

