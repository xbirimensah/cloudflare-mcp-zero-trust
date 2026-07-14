# Agent guidance

## Scope

This repository is a generic Cloudflare Access boundary for MCP servers. Keep it
independent of any specific product, owner, data domain, tunnel name, account,
email, or hostname.

## Invariants

- Do not create, delete, or broaden identity policies automatically.
- Accept only exact-email allow rules; bypass and broad rules must fail closed.
- Keep Cloudflare writes behind the explicit `apply` command.
- Never log or persist API tokens, JWTs, audience tags, or email identities.
- Preserve unrelated fields on the existing Access application.
- Keep loopback origin access and public Cloudflare-forwarded access distinct.
- Do not weaken assertion verification to make a client integration pass.

## Workflow

Use test-driven development for boundary changes. Before release, run tests with
80% coverage, Ruff, Pyright, `pip-audit`, a secrets scan, and a package build.
Review the final tracked tree for product- or owner-specific values.

