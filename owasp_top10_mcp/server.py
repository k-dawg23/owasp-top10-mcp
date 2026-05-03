"""MCP stdio server: owasp_scan (JSON) and owasp_report (Markdown)."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from owasp_top10_mcp.scan.engine import run_scan
from owasp_top10_mcp.scan.markdown import render_markdown

mcp = FastMCP("owasp-top10-mcp", json_response=True)


@mcp.tool()
def owasp_scan(
    repo_root: str,
    categories: list[str] | None = None,
    profile: str = "agent_quick",
    max_files: int | None = None,
    max_bytes_per_file: int | None = None,
    max_total_bytes: int | None = None,
    time_budget_ms: int | None = None,
    severity_floor: str | None = None,
) -> dict[str, Any]:
    """Static OWASP Top 10:2025-oriented scan. Returns versioned JSON only (no Markdown).

    Args:
        repo_root: Absolute path to repository root to scan.
        categories: Optional subset of A01..A10 (e.g. ["A05"]). Omit for all categories.
        profile: agent_quick (faster, higher severity floor) or human_full.
        max_files, max_bytes_per_file, max_total_bytes, time_budget_ms, severity_floor:
            Optional overrides for scan limits (see design defaults).
    """
    return run_scan(
        repo_root=repo_root,
        categories=categories,
        profile=profile,
        max_files=max_files,
        max_bytes_per_file=max_bytes_per_file,
        max_total_bytes=max_total_bytes,
        time_budget_ms=time_budget_ms,
        severity_floor=severity_floor,
    )


@mcp.tool()
def owasp_report(
    repo_root: str,
    categories: list[str] | None = None,
    profile: str = "agent_quick",
    max_files: int | None = None,
    max_bytes_per_file: int | None = None,
    max_total_bytes: int | None = None,
    time_budget_ms: int | None = None,
    severity_floor: str | None = None,
) -> str:
    """Same scan as owasp_scan with identical parameters; returns a Markdown report body."""
    envelope = run_scan(
        repo_root=repo_root,
        categories=categories,
        profile=profile,
        max_files=max_files,
        max_bytes_per_file=max_bytes_per_file,
        max_total_bytes=max_total_bytes,
        time_budget_ms=time_budget_ms,
        severity_floor=severity_floor,
    )
    return render_markdown(envelope)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
