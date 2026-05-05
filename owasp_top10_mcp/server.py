"""MCP stdio server: owasp_scan (JSON), owasp_report (Markdown), save-to-disk tools."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from owasp_top10_mcp.report_save import save_markdown_report, save_scan_json
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
    """Return the versioned JSON findings envelope for a static OWASP Top 10:2025-oriented scan (no Markdown).

    Use when the MCP client needs structured data for automation or downstream tools.
    For a human-readable report with navigable OWASP, CWE, and related links, call
    ``owasp_report`` instead. Neither this tool nor ``owasp_report`` writes files; use
    ``owasp_report_save`` or ``owasp_scan_save`` when the client supplies a destination path.

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
    """Return the Markdown report body for the same scan as ``owasp_scan`` (identical parameters).

    Use when someone will read the report in an MCP client or copy it manually. The Markdown
    includes navigable links where implemented; ``owasp_scan`` returns only JSON without that
    layout. To persist Markdown to disk in one call, use ``owasp_report_save`` with an absolute
    ``output_path``.
    """
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


@mcp.tool()
def owasp_report_save(
    repo_root: str,
    output_path: str,
    overwrite: bool = False,
    categories: list[str] | None = None,
    profile: str = "agent_quick",
    max_files: int | None = None,
    max_bytes_per_file: int | None = None,
    max_total_bytes: int | None = None,
    time_budget_ms: int | None = None,
    severity_floor: str | None = None,
) -> dict[str, Any]:
    """Write the Markdown report (same as ``owasp_report``) to ``output_path``; return confirmation JSON.

    Use when the client needs the report on disk (tickets, PRs, archives) without pasting from
    chat. Only the file at the supplied path is written; the scanned repository tree is not
    modified by scan logic. For the JSON envelope on disk, use ``owasp_scan_save`` instead.
    ``output_path`` must be absolute; parent directories are created as needed; set
    ``overwrite`` to replace an existing file.

    Returns a small JSON object (path, byte size, truncated, rulepack and product version);
    the full Markdown is not included in the tool result.
    """
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
    return save_markdown_report(envelope, output_path, overwrite=overwrite)


@mcp.tool()
def owasp_scan_save(
    repo_root: str,
    output_path: str,
    overwrite: bool = False,
    categories: list[str] | None = None,
    profile: str = "agent_quick",
    max_files: int | None = None,
    max_bytes_per_file: int | None = None,
    max_total_bytes: int | None = None,
    time_budget_ms: int | None = None,
    severity_floor: str | None = None,
) -> dict[str, Any]:
    """Write the scan JSON envelope (same object as ``owasp_scan``) to ``output_path``; return confirmation only.

    Use when the MCP client needs the full structured envelope on disk (CI, tickets, archives)
    without pasting tool output. For Markdown with navigable links, use ``owasp_report_save``;
    for JSON in the tool result only, use ``owasp_scan``.

    The file body is ``json.dumps(envelope, indent=2, ensure_ascii=False)`` plus one
    trailing newline (UTF-8). ``output_path`` must be absolute; ``~`` is expanded.
    Parent directories are created if needed. Existing files are not overwritten
    unless ``overwrite`` is true.

    Returns a small JSON object (path, bytes, finding count, truncated, rulepack and
    product version); the full scan payload is not included in the tool result.
    """
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
    return save_scan_json(envelope, output_path, overwrite=overwrite)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
