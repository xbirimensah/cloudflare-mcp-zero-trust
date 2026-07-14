"""Safe plan/apply CLI for Cloudflare Access Managed OAuth."""

from __future__ import annotations

import json

import typer

from .cloudflare_api import (
    CloudflareConfigurationError,
    ManagedOAuthClient,
)


app = typer.Typer(
    no_args_is_help=True, help="Secure one MCP endpoint with Cloudflare Access."
)


def _client() -> ManagedOAuthClient:
    return ManagedOAuthClient.from_environment()


@app.callback()
def _root() -> None:
    """Plan or apply a narrow, exact-identity Managed OAuth configuration."""


@app.command()
def plan(
    host: str = typer.Option(..., help="Exact public MCP DNS host."),
) -> None:
    """Validate and print a redacted plan without changing Cloudflare."""
    try:
        summary = _client().plan(host).summary()
    except (CloudflareConfigurationError, RuntimeError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(1) from error
    typer.echo(json.dumps(summary, indent=2, sort_keys=True))
    typer.echo("No Cloudflare application was changed.")


@app.command()
def apply(
    host: str = typer.Option(..., help="Exact public MCP DNS host."),
    redirect_uri: list[str] | None = typer.Option(
        None,
        help="Explicit HTTPS OAuth callback. Repeat for multiple clients.",
    ),
) -> None:
    """Idempotently enable Managed OAuth and safe dynamic registration."""
    try:
        changed = _client().apply(host, redirect_uris=tuple(redirect_uri or ()))
    except (CloudflareConfigurationError, RuntimeError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(1) from error
    if changed:
        typer.echo("Cloudflare Managed OAuth configuration updated.")
    else:
        typer.echo("Cloudflare Managed OAuth is already configured.")
