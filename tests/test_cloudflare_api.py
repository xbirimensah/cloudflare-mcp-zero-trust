import json

import httpx
import pytest

from cloudflare_mcp_zero_trust.cloudflare_api import (
    CloudflareConfigurationError,
    ManagedOAuthClient,
)


def managed_application(*, enabled: bool = False) -> dict[str, object]:
    registration: dict[str, object] = {
        "enabled": enabled,
        "allowed_uris": ["https://client.example/callback"],
    }
    oauth: dict[str, object] = {
        "enabled": enabled,
        "dynamic_client_registration": registration,
    }
    if enabled:
        registration.update(
            {
                "allow_any_on_localhost": True,
                "allow_any_on_loopback": True,
            }
        )
        oauth["grant"] = {
            "access_token_lifetime": "15m",
            "session_duration": "336h",
        }
    return {
        "id": "application-id",
        "name": "Example MCP",
        "type": "self_hosted",
        "domain": "mcp.example.com",
        "aud": "a" * 64,
        "custom_deny_url": "https://example.com/denied",
        "policies": [
            {
                "id": "policy-id",
                "name": "Exact users",
                "decision": "allow",
                "include": [{"email": {"email": "owner@example.com"}}],
                "exclude": [],
                "require": [],
            }
        ],
        "oauth_configuration": oauth,
    }


def managed_client(handler) -> ManagedOAuthClient:
    return ManagedOAuthClient(
        account_id="account-id",
        application_id="application-id",
        api_token="test-token",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


def test_plan_is_redacted_and_validates_exact_email_policies() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"success": True, "result": managed_application()})

    plan = managed_client(handler).plan("mcp.example.com")

    assert plan.summary() == {
        "application_id": "application-id",
        "application_name": "Example MCP",
        "application_type": "self_hosted",
        "domain": "mcp.example.com",
        "managed_oauth_enabled": False,
        "exact_allowed_identities": 1,
    }
    assert "owner@example.com" not in repr(plan)
    assert "a" * 64 not in repr(plan)


def test_apply_preserves_application_and_adds_cli_and_https_callbacks() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "GET":
            return httpx.Response(200, json={"success": True, "result": managed_application()})
        payload = json.loads(request.content)
        assert payload["name"] == "Example MCP"
        assert payload["custom_deny_url"] == "https://example.com/denied"
        assert payload["policies"][0]["name"] == "Exact users"
        oauth = payload["oauth_configuration"]
        assert oauth["enabled"] is True
        assert oauth["dynamic_client_registration"] == {
            "enabled": True,
            "allow_any_on_localhost": True,
            "allow_any_on_loopback": True,
            "allowed_uris": [
                "https://client.example/callback",
                "https://claude.ai/api/mcp/auth_callback",
            ],
        }
        assert oauth["grant"] == {
            "access_token_lifetime": "15m",
            "session_duration": "336h",
        }
        return httpx.Response(200, json={"success": True, "result": payload})

    changed = managed_client(handler).apply(
        "mcp.example.com",
        redirect_uris=("https://claude.ai/api/mcp/auth_callback",),
    )

    assert changed is True
    assert [request.method for request in requests] == ["GET", "PUT"]
    assert requests[1].headers["Authorization"] == "Bearer test-token"


def test_apply_is_idempotent_when_requested_callbacks_already_exist() -> None:
    requests: list[httpx.Request] = []
    application = managed_application(enabled=True)

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"success": True, "result": application})

    changed = managed_client(handler).apply(
        "mcp.example.com",
        redirect_uris=("https://client.example/callback",),
    )

    assert changed is False
    assert [request.method for request in requests] == ["GET"]


@pytest.mark.parametrize(
    "redirect_uri",
    [
        "http://client.example/callback",
        "https://user@client.example/callback",
        "https://client.example/callback#fragment",
        "https://client.example/*/callback",
    ],
)
def test_apply_rejects_unsafe_dynamic_client_redirects(redirect_uri: str) -> None:
    with pytest.raises(CloudflareConfigurationError, match="redirect URI"):
        managed_client(lambda _request: None).apply(
            "mcp.example.com",
            redirect_uris=(redirect_uri,),
        )


@pytest.mark.parametrize(
    "policy",
    [
        {"id": "bad", "decision": "bypass", "include": []},
        {"id": "bad", "decision": "allow", "include": [{"everyone": {}}]},
        {
            "id": "bad",
            "decision": "allow",
            "include": [{"email_domain": {"domain": "example.com"}}],
        },
    ],
)
def test_plan_refuses_broad_or_bypass_policies(policy: dict[str, object]) -> None:
    application = managed_application()
    application["policies"] = [policy]

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"success": True, "result": application})

    with pytest.raises(RuntimeError, match="exact email allow policies"):
        managed_client(handler).plan("mcp.example.com")
