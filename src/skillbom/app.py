from __future__ import annotations

from typing import Annotated

import typer

from skillbom import __version__
from skillbom.cli import gate, init, init_policy, lock_manifest
from skillbom.commands_diff import diff_command, repo_diff_command
from skillbom.commands_scan import scan_command

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="Scan Agent Skills, MCP servers, and AI tool repositories without executing them.",
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"skillbom {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    """Inspect Agent Skills and AI tool repositories without executing them."""


app.command("init")(init)
app.command("lock")(lock_manifest)
app.command("gate")(gate)
app.command("init-policy")(init_policy)

app.command("scan")(scan_command)
app.command("diff")(diff_command)
app.command("repo-diff")(repo_diff_command)
