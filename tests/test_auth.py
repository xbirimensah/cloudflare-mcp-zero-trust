from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from cloudflare_mcp_zero_trust.auth import (
    AccessJWTMiddleware,
    AccessJWTVerifier,
    ManagedOAuthError,
    ManagedOAuthSettings,
)


AUDIENCE = "a" * 64
TEAM_DOMAIN = "https://team.cloudflareaccess.com"
PUBLIC_HOST = "mcp.example.com"
OWNER_EMAIL = "owner@example.com"


def managed_environment(**overrides: str) -> dict[str, str]:
    environment = {
        "CF_MCP_TEAM_DOMAIN": TEAM_DOMAIN,
        "CF_MCP_ACCESS_AUDIENCE": AUDIENCE,
        "CF_MCP_ALLOWED_EMAILS": OWNER_EMAIL,
        "CF_MCP_PUBLIC_HOST": PUBLIC_HOST,
    }
    environment.update(overrides)
    return environment


def test_settings_are_all_or_nothing_and_reject_unsafe_team_origins() -> None:
    assert ManagedOAuthSettings.from_environ({}) is None
    assert ManagedOAuthSettings.from_environ({"CF_MCP_PUBLIC_HOST": PUBLIC_HOST}) is None

    with pytest.raises(ManagedOAuthError, match="Incomplete Managed OAuth"):
        ManagedOAuthSettings.from_environ({"CF_MCP_TEAM_DOMAIN": TEAM_DOMAIN})

    for unsafe in (
        "http://team.cloudflareaccess.com",
        "https://team.cloudflareaccess.com/path",
        "https://team.cloudflareaccess.com.evil.example",
        "https://user@team.cloudflareaccess.com",
        "https://127.0.0.1",
    ):
        with pytest.raises(ManagedOAuthError, match="Cloudflare Access team origin"):
            ManagedOAuthSettings.from_environ(
                managed_environment(CF_MCP_TEAM_DOMAIN=unsafe)
            )


def test_settings_normalize_exact_email_allowlist_and_redact_it() -> None:
    settings = ManagedOAuthSettings.from_environ(
        managed_environment(CF_MCP_ALLOWED_EMAILS=" OWNER@EXAMPLE.COM ")
    )

    assert settings is not None
    assert settings.allowed_emails == frozenset({OWNER_EMAIL})
    assert OWNER_EMAIL not in repr(settings)
    assert AUDIENCE not in repr(settings)
    assert settings.jwks_url == f"{TEAM_DOMAIN}/cdn-cgi/access/certs"


def _signed_token(
    private_key: rsa.RSAPrivateKey,
    *,
    audience: str = AUDIENCE,
    issuer: str = TEAM_DOMAIN,
    email: str = OWNER_EMAIL,
    token_type: str = "app",
) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "aud": [audience],
            "email": email,
            "exp": now + timedelta(minutes=5),
            "iat": now,
            "nbf": now - timedelta(seconds=1),
            "iss": issuer,
            "sub": "authorized-subject",
            "type": token_type,
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )


def _client() -> tuple[TestClient, rsa.RSAPrivateKey]:
    settings = ManagedOAuthSettings.from_environ(managed_environment())
    assert settings is not None
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier = AccessJWTVerifier(
        settings,
        signing_key_resolver=lambda _token: private_key.public_key(),
    )

    async def status(request: Request) -> JSONResponse:
        identity = getattr(request.state, "cloudflare_access_identity", None)
        return JSONResponse({"ok": True, "identity": identity})

    app = Starlette(routes=[Route("/mcp", status, methods=["GET", "POST"])])
    return TestClient(AccessJWTMiddleware(app, verifier)), private_key


def test_loopback_requests_remain_available_without_cloudflare_headers() -> None:
    client, _private_key = _client()

    response = client.get("http://127.0.0.1:8791/mcp")

    assert response.status_code == 200
    assert response.json() == {"ok": True, "identity": None}


def test_public_host_requires_and_records_one_verified_access_assertion() -> None:
    client, private_key = _client()

    missing = client.get(f"https://{PUBLIC_HOST}/mcp")
    valid = client.get(
        f"https://{PUBLIC_HOST}/mcp",
        headers={"Cf-Access-Jwt-Assertion": _signed_token(private_key)},
    )

    assert missing.status_code == 403
    assert missing.json() == {"error": "Cloudflare Access authentication failed"}
    assert valid.status_code == 200
    assert valid.json()["identity"] == {
        "email": OWNER_EMAIL,
        "subject": "authorized-subject",
    }


@pytest.mark.parametrize(
    ("claim", "value"),
    [
        ("audience", "b" * 64),
        ("issuer", "https://other.cloudflareaccess.com"),
        ("email", "not-owner@example.com"),
        ("token_type", "org"),
    ],
)
def test_public_host_rejects_wrong_audience_issuer_identity_or_token_type(
    claim: str,
    value: str,
) -> None:
    client, private_key = _client()

    response = client.get(
        f"https://{PUBLIC_HOST}/mcp",
        headers={"Cf-Access-Jwt-Assertion": _signed_token(private_key, **{claim: value})},
    )

    assert response.status_code == 403


def test_spoofed_cloudflare_forwarding_header_also_requires_an_assertion() -> None:
    client, _private_key = _client()

    response = client.get(
        "http://127.0.0.1:8791/mcp",
        headers={"Cf-Ray": "test-edge-id"},
    )

    assert response.status_code == 403
