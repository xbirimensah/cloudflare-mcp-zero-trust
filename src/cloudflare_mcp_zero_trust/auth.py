"""Verify Cloudflare Access assertions at an MCP origin boundary."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import ipaddress
import json
import re
from typing import Any, Callable, Mapping
from urllib.parse import urlparse

import jwt
from starlette.types import ASGIApp, Receive, Scope, Send


_AUDIENCE = re.compile(r"^[A-Za-z0-9_-]{20,64}$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_NAMES = (
    "CF_MCP_TEAM_DOMAIN",
    "CF_MCP_ACCESS_AUDIENCE",
    "CF_MCP_ALLOWED_EMAILS",
    "CF_MCP_PUBLIC_HOST",
)
_TRUST_NAMES = _NAMES[:-1]
_MAX_ASSERTION_BYTES = 16 * 1024
_DENIED_BODY = json.dumps(
    {"error": "Cloudflare Access authentication failed"},
    separators=(",", ":"),
).encode("utf-8")


class ManagedOAuthError(RuntimeError):
    """Managed OAuth configuration or an origin assertion is invalid."""


def normalize_email(value: str) -> str:
    """Normalize and validate one exact email identity."""
    email = value.strip().lower()
    if not _EMAIL.fullmatch(email):
        raise ValueError("A valid exact email address is required")
    return email


@dataclass(frozen=True)
class ManagedOAuthSettings:
    """Validated public route and private Access identity configuration."""

    team_domain: str
    public_host: str
    audience: str = field(repr=False)
    allowed_emails: frozenset[str] = field(repr=False)

    @classmethod
    def from_environ(
        cls,
        environ: Mapping[str, str],
    ) -> ManagedOAuthSettings | None:
        values = {name: environ.get(name, "").strip() for name in _NAMES}
        configured_trust = [name for name in _TRUST_NAMES if values[name]]
        if not configured_trust:
            return None
        missing = [name for name, value in values.items() if not value]
        if missing:
            raise ManagedOAuthError(
                "Incomplete Managed OAuth configuration; missing: " + ", ".join(missing)
            )

        team_domain = _validated_team_domain(values["CF_MCP_TEAM_DOMAIN"])
        public_host = _validated_public_host(values["CF_MCP_PUBLIC_HOST"])
        audience = values["CF_MCP_ACCESS_AUDIENCE"]
        if _AUDIENCE.fullmatch(audience) is None:
            raise ManagedOAuthError(
                "CF_MCP_ACCESS_AUDIENCE must be a valid Access audience tag"
            )
        try:
            allowed_emails = frozenset(
                normalize_email(email)
                for email in values["CF_MCP_ALLOWED_EMAILS"].split(",")
                if email.strip()
            )
        except ValueError as error:
            raise ManagedOAuthError(
                "CF_MCP_ALLOWED_EMAILS must contain valid exact email addresses"
            ) from error
        if not allowed_emails or len(allowed_emails) > 20:
            raise ManagedOAuthError(
                "CF_MCP_ALLOWED_EMAILS must contain one to twenty exact identities"
            )
        return cls(team_domain, public_host, audience, allowed_emails)

    @property
    def jwks_url(self) -> str:
        return f"{self.team_domain}/cdn-cgi/access/certs"


class AccessJWTVerifier:
    """Verify Access signature, issuer, audience, type, and exact identity."""

    def __init__(
        self,
        settings: ManagedOAuthSettings,
        *,
        signing_key_resolver: Callable[[str], Any] | None = None,
    ) -> None:
        self.settings = settings
        if signing_key_resolver is None:
            jwks = jwt.PyJWKClient(
                settings.jwks_url,
                cache_keys=True,
                lifespan=300,
                timeout=10,
            )

            def resolve_signing_key(token: str) -> Any:
                return jwks.get_signing_key_from_jwt(token).key

            signing_key_resolver = resolve_signing_key
        self._signing_key_resolver = signing_key_resolver

    def verify(self, token: str) -> dict[str, str]:
        if not token or len(token.encode("utf-8")) > _MAX_ASSERTION_BYTES:
            raise ManagedOAuthError("Cloudflare Access assertion is invalid")
        try:
            claims = jwt.decode(
                token,
                key=self._signing_key_resolver(token),
                algorithms=["RS256"],
                audience=self.settings.audience,
                issuer=self.settings.team_domain,
                leeway=30,
                options={
                    "require": [
                        "aud",
                        "email",
                        "exp",
                        "iat",
                        "nbf",
                        "iss",
                        "sub",
                        "type",
                    ]
                },
            )
            email = normalize_email(str(claims["email"]))
            subject = str(claims["sub"])
        except (jwt.PyJWTError, KeyError, OSError, TypeError, ValueError) as error:
            raise ManagedOAuthError("Cloudflare Access assertion is invalid") from error
        if (
            claims.get("type") != "app"
            or not subject
            or email not in self.settings.allowed_emails
        ):
            raise ManagedOAuthError("Cloudflare Access assertion is not authorized")
        return {"email": email, "subject": subject}


class AccessJWTMiddleware:
    """Require an assertion for the public host or Cloudflare-forwarded traffic."""

    def __init__(self, app: ASGIApp, verifier: AccessJWTVerifier) -> None:
        self.app = app
        self.verifier = verifier

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return
        headers = [(name.lower(), value) for name, value in scope.get("headers", [])]
        public_host = _header_host(headers) == self.verifier.settings.public_host
        forwarded = any(
            name in {b"cf-connecting-ip", b"cf-ray"} for name, _value in headers
        )
        try:
            assertions = [
                value.decode("utf-8", errors="strict")
                for name, value in headers
                if name == b"cf-access-jwt-assertion"
            ]
        except UnicodeError:
            assertions = ["", ""]
        if public_host or forwarded or assertions:
            try:
                if len(assertions) != 1:
                    raise ManagedOAuthError("Cloudflare Access assertion is missing")
                identity = await asyncio.to_thread(self.verifier.verify, assertions[0])
            except ManagedOAuthError:
                await _deny(send, websocket=scope["type"] == "websocket")
                return
            forwarded_scope = dict(scope)
            state = dict(scope.get("state", {}))
            state["cloudflare_access_identity"] = identity
            forwarded_scope["state"] = state
            await self.app(forwarded_scope, receive, send)
            return
        await self.app(scope, receive, send)


async def _deny(send: Send, *, websocket: bool) -> None:
    if websocket:
        await send({"type": "websocket.close", "code": 1008, "reason": "Access denied"})
        return
    await send(
        {
            "type": "http.response.start",
            "status": 403,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(_DENIED_BODY)).encode("ascii")),
                (b"cache-control", b"no-store"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": _DENIED_BODY})


def _header_host(headers: list[tuple[bytes, bytes]]) -> str:
    values = [value for name, value in headers if name == b"host"]
    if len(values) != 1:
        return ""
    try:
        return (
            (urlparse("//" + values[0].decode("ascii")).hostname or "")
            .rstrip(".")
            .lower()
        )
    except (UnicodeError, ValueError):
        return ""


def _validated_team_domain(value: str) -> str:
    parsed = urlparse(value)
    host = (parsed.hostname or "").rstrip(".").lower()
    try:
        port = parsed.port
    except ValueError:
        port = -1
    if (
        parsed.scheme != "https"
        or not host.endswith(".cloudflareaccess.com")
        or host == "cloudflareaccess.com"
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or port not in (None, 443)
        or not _is_public_dns_name(host)
    ):
        raise ManagedOAuthError(
            "CF_MCP_TEAM_DOMAIN must be a Cloudflare Access team origin"
        )
    return f"https://{host}"


def _validated_public_host(value: str) -> str:
    host = value.rstrip(".").lower()
    if not _is_public_dns_name(host):
        raise ManagedOAuthError("CF_MCP_PUBLIC_HOST must be a public DNS hostname")
    return host


def _is_public_dns_name(host: str) -> bool:
    if (
        not host
        or len(host) > 253
        or "." not in host
        or any(char.isspace() for char in host)
    ):
        return False
    if any(char in host for char in ":/@?#[]"):
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return False
    return all(_HOST_LABEL.fullmatch(label) for label in host.split("."))
