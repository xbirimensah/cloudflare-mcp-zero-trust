"""Narrow Cloudflare API reconciliation for Managed OAuth on one Access app."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
import ipaddress
import os
import re
from typing import Any
from urllib.parse import urlparse

import httpx

from .auth import normalize_email


API_BASE_URL = "https://api.cloudflare.com/client/v4"
_PATH_SEGMENT = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


class CloudflareConfigurationError(ValueError):
    """Cloudflare provisioning configuration is absent or unsafe."""


@dataclass(frozen=True)
class ManagedOAuthPlan:
    """Validated plan whose representation intentionally redacts identities."""

    application_id: str
    application_name: str
    application_type: str
    domain: str
    managed_oauth_enabled: bool
    exact_allowed_identities: int
    audience: str = field(repr=False)
    allowed_emails: frozenset[str] = field(repr=False)

    def summary(self) -> dict[str, str | bool | int]:
        return {
            "application_id": self.application_id,
            "application_name": self.application_name,
            "application_type": self.application_type,
            "domain": self.domain,
            "managed_oauth_enabled": self.managed_oauth_enabled,
            "exact_allowed_identities": self.exact_allowed_identities,
        }


@dataclass
class ManagedOAuthClient:
    """Plan and idempotently reconcile one existing self-hosted Access app."""

    account_id: str
    application_id: str
    api_token: str = field(repr=False)
    http_client: httpx.Client | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        self.account_id = _path_segment(self.account_id, "CLOUDFLARE_ACCOUNT_ID")
        self.application_id = _path_segment(
            self.application_id,
            "CLOUDFLARE_ACCESS_APPLICATION_ID",
        )
        if not self.api_token.strip():
            raise CloudflareConfigurationError("CLOUDFLARE_API_TOKEN must not be empty")

    @classmethod
    def from_environment(cls) -> ManagedOAuthClient:
        names = (
            "CLOUDFLARE_API_TOKEN",
            "CLOUDFLARE_ACCOUNT_ID",
            "CLOUDFLARE_ACCESS_APPLICATION_ID",
        )
        values = {name: os.environ.get(name, "").strip() for name in names}
        missing = [name for name, value in values.items() if not value]
        if missing:
            raise CloudflareConfigurationError(
                "Missing runtime configuration: " + ", ".join(missing)
            )
        return cls(
            account_id=values["CLOUDFLARE_ACCOUNT_ID"],
            application_id=values["CLOUDFLARE_ACCESS_APPLICATION_ID"],
            api_token=values["CLOUDFLARE_API_TOKEN"],
        )

    @property
    def application_path(self) -> str:
        return f"/accounts/{self.account_id}/access/apps/{self.application_id}"

    def plan(self, host: str) -> ManagedOAuthPlan:
        """Validate and summarize the target without changing Cloudflare."""
        _application, plan = self._validated_application(host)
        return plan

    def apply(self, host: str, *, redirect_uris: tuple[str, ...] = ()) -> bool:
        """Enable safe Managed OAuth settings without replacing app policy."""
        validated_uris = tuple(_redirect_uri(uri) for uri in redirect_uris)
        application, _plan = self._validated_application(host)
        payload = deepcopy(application)
        existing_oauth = payload.get("oauth_configuration")
        oauth = dict(existing_oauth) if isinstance(existing_oauth, dict) else {}
        oauth["enabled"] = True
        existing_registration = oauth.get("dynamic_client_registration")
        registration = (
            dict(existing_registration)
            if isinstance(existing_registration, dict)
            else {}
        )
        existing_allowed = registration.get("allowed_uris")
        allowed = (
            [str(uri) for uri in existing_allowed]
            if isinstance(existing_allowed, list)
            else []
        )
        for uri in validated_uris:
            if uri not in allowed:
                allowed.append(uri)
        registration.update(
            {
                "enabled": True,
                "allow_any_on_localhost": True,
                "allow_any_on_loopback": True,
                "allowed_uris": allowed,
            }
        )
        oauth["dynamic_client_registration"] = registration
        existing_grant = oauth.get("grant")
        grant = dict(existing_grant) if isinstance(existing_grant, dict) else {}
        grant.setdefault("access_token_lifetime", "15m")
        grant.setdefault("session_duration", "336h")
        oauth["grant"] = grant
        if oauth == existing_oauth:
            return False
        payload["oauth_configuration"] = oauth
        self._request("PUT", json=payload)
        return True

    def _validated_application(
        self,
        host: str,
    ) -> tuple[dict[str, Any], ManagedOAuthPlan]:
        normalized_host = _public_host(host)
        application = self._request("GET")
        if application.get("id") != self.application_id:
            raise RuntimeError("Cloudflare Access returned a different application")
        if application.get("type") != "self_hosted":
            raise RuntimeError(
                "Cloudflare Access target must be a self-hosted application"
            )
        if str(application.get("domain", "")).rstrip(".").lower() != normalized_host:
            raise RuntimeError(
                "Cloudflare Access application does not match the public host"
            )
        name = application.get("name")
        audience = application.get("aud")
        if not isinstance(name, str) or not name.strip():
            raise RuntimeError(
                "Cloudflare Access application must have a readable name"
            )
        if not isinstance(audience, str) or not audience.strip():
            raise RuntimeError(
                "Cloudflare Access application must have an audience tag"
            )
        emails = _exact_emails(application.get("policies"))
        oauth = application.get("oauth_configuration")
        enabled = isinstance(oauth, dict) and oauth.get("enabled") is True
        return application, ManagedOAuthPlan(
            self.application_id,
            name,
            "self_hosted",
            normalized_host,
            enabled,
            len(emails),
            audience,
            emails,
        )

    def _request(self, method: str, **kwargs: Any) -> dict[str, Any]:
        client = self.http_client or httpx.Client(timeout=30)
        close_client = self.http_client is None
        try:
            response = client.request(
                method,
                f"{API_BASE_URL}{self.application_path}",
                headers={"Authorization": f"Bearer {self.api_token}"},
                **kwargs,
            )
            try:
                payload = response.json()
            except ValueError as error:
                raise RuntimeError("Cloudflare returned a non-JSON response") from error
            if response.is_error or not payload.get("success", False):
                errors = payload.get("errors")
                if isinstance(errors, list):
                    message = "; ".join(
                        str(item.get("message", "Cloudflare API request failed"))
                        for item in errors
                        if isinstance(item, dict)
                    )
                else:
                    message = response.reason_phrase
                raise RuntimeError(f"Cloudflare Access API request failed: {message}")
            result = payload.get("result")
            if not isinstance(result, dict):
                raise RuntimeError(
                    "Cloudflare Access API returned an unexpected response"
                )
            return result
        finally:
            if close_client:
                client.close()


def _path_segment(value: str, name: str) -> str:
    if _PATH_SEGMENT.fullmatch(value) is None:
        raise CloudflareConfigurationError(f"{name} must be one opaque identifier")
    return value


def _public_host(value: str) -> str:
    host = value.strip().rstrip(".").lower()
    if (
        not host
        or len(host) > 253
        or "." not in host
        or any(char in host for char in ":/@?#[]")
        or not all(_HOST_LABEL.fullmatch(label) for label in host.split("."))
    ):
        raise CloudflareConfigurationError("host must be a public DNS hostname")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    raise CloudflareConfigurationError("host must be a public DNS hostname")


def _redirect_uri(value: str) -> str:
    uri = value.strip()
    parsed = urlparse(uri)
    host = parsed.hostname or ""
    wildcard = host.startswith("*.") or "*" in parsed.path
    allowed_trailing_wildcard = (
        parsed.path.endswith("/*") and parsed.path.count("*") == 1
    )
    if (
        parsed.scheme != "https"
        or not host
        or parsed.username
        or parsed.password
        or parsed.fragment
        or parsed.query
        or (wildcard and not allowed_trailing_wildcard)
        or "*" in host
    ):
        raise CloudflareConfigurationError(
            "redirect URI must be an explicit HTTPS endpoint"
        )
    return uri


def _exact_emails(value: object) -> frozenset[str]:
    if not isinstance(value, list) or not value:
        raise RuntimeError(
            "Cloudflare Access application must use exact email allow policies"
        )
    emails: set[str] = set()
    for policy in value:
        if not isinstance(policy, dict) or policy.get("decision") == "bypass":
            raise RuntimeError(
                "Cloudflare Access application must use exact email allow policies"
            )
        if policy.get("decision") != "allow":
            continue
        include = policy.get("include")
        if not isinstance(include, list) or not include:
            raise RuntimeError(
                "Cloudflare Access application must use exact email allow policies"
            )
        for rule in include:
            if not isinstance(rule, dict) or set(rule) != {"email"}:
                raise RuntimeError(
                    "Cloudflare Access application must use exact email allow policies"
                )
            email_rule = rule.get("email")
            if not isinstance(email_rule, dict) or set(email_rule) != {"email"}:
                raise RuntimeError(
                    "Cloudflare Access application must use exact email allow policies"
                )
            try:
                emails.add(normalize_email(str(email_rule["email"])))
            except (KeyError, ValueError) as error:
                raise RuntimeError(
                    "Cloudflare Access application must use exact email allow policies"
                ) from error
    if not emails or len(emails) > 20:
        raise RuntimeError(
            "Cloudflare Access application must use exact email allow policies"
        )
    return frozenset(emails)
