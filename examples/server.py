"""Minimal FastMCP server protected by Cloudflare Access at the origin."""

from __future__ import annotations

import os

from fastmcp import FastMCP
from starlette.middleware import Middleware

from cloudflare_mcp_zero_trust import (
    AccessJWTMiddleware,
    AccessJWTVerifier,
    ManagedOAuthSettings,
)


def create_server() -> FastMCP:
    server = FastMCP("Protected Example")

    @server.tool()
    def status() -> dict[str, bool]:
        """Return a deliberately non-sensitive liveness result."""
        return {"ok": True}

    return server


def run() -> None:
    settings = ManagedOAuthSettings.from_environ(os.environ)
    if settings is None:
        raise RuntimeError("CF_MCP_* origin trust settings are required")
    server = create_server()
    server.run(
        transport="streamable-http",
        host="127.0.0.1",
        port=int(os.environ.get("MCP_PORT", "8791")),
        path="/mcp",
        stateless_http=True,
        middleware=[
            Middleware(AccessJWTMiddleware, verifier=AccessJWTVerifier(settings))
        ],
    )


if __name__ == "__main__":
    run()
