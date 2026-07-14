from typer.testing import CliRunner

from cloudflare_mcp_zero_trust.cli import app


def test_plan_prints_only_redacted_application_summary(monkeypatch) -> None:
    class FakePlan:
        def summary(self):
            return {
                "application_id": "application-id",
                "application_name": "Example MCP",
                "domain": "mcp.example.com",
                "managed_oauth_enabled": True,
                "exact_allowed_identities": 1,
            }

    class FakeClient:
        def plan(self, host):
            assert host == "mcp.example.com"
            return FakePlan()

    monkeypatch.setattr(
        "cloudflare_mcp_zero_trust.cli._client",
        lambda: FakeClient(),
    )

    result = CliRunner().invoke(app, ["plan", "--host", "mcp.example.com"])

    assert result.exit_code == 0
    assert "Example MCP" in result.stdout
    assert "owner@example.com" not in result.stdout
    assert "No Cloudflare application was changed" in result.stdout


def test_apply_passes_explicit_redirects_and_reports_idempotence(monkeypatch) -> None:
    observed = []

    class FakeClient:
        def apply(self, host, *, redirect_uris):
            observed.append((host, redirect_uris))
            return False

    monkeypatch.setattr(
        "cloudflare_mcp_zero_trust.cli._client",
        lambda: FakeClient(),
    )

    result = CliRunner().invoke(
        app,
        [
            "apply",
            "--host",
            "mcp.example.com",
            "--redirect-uri",
            "https://claude.ai/api/mcp/auth_callback",
        ],
    )

    assert result.exit_code == 0
    assert observed == [
        (
            "mcp.example.com",
            ("https://claude.ai/api/mcp/auth_callback",),
        )
    ]
    assert "already configured" in result.stdout
