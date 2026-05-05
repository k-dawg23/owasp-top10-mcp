## Context

The shipped server exposes **`owasp_scan`**, **`owasp_report`**, and **`owasp_report_save`**. The main OpenSpec file still has a **TBD** **Purpose** and an introductory requirement that lists only two tools. Solo users and agents need a **single coherent story**: JSON vs Markdown vs save-to-disk, and how that coexists with **no silent remediation**.

## Goals / Non-Goals

**Goals:**

- **Spec truth:** Preamble and requirements match shipped tools and limits.
- **Agent UX:** Tool descriptions and README make **which tool** obvious without vendor-specific MCP extensions.
- **Trust:** **No silent remediation** explicitly allows **client-chosen** Markdown persistence via **`owasp_report_save`**; scan tools do not mutate the **scanned repo**.

**Non-Goals:**

- PyPI releases, versioning policy changes, new tools, new rules, or deeper static analysis.

## Decisions

### D1 - Purpose paragraph (verbatim target for `## Purpose`)

Use prose equivalent to:

> **owasp-top10-mcp** is a **local** Model Context Protocol (MCP) server using **stdio**. It targets **solo developers and AI agents** who want a **fast, offline-capable, static** read of a repository against **OWASP Top 10:2025** themes (**A01–A10**). It does **not** require a hosted service or **PyPI** for end-user operation: a **git clone**, **venv**, and MCP config suffice. Findings are **advisory**; default scans do not run external security binaries or advisory APIs.

### D2 - Three-tool summary in the first requirement

The **Local MCP server exposes…** requirement SHALL name all three tools and their **primary artifacts** (JSON / Markdown string / save+confirmation JSON).

### D3 - No silent remediation carve-out

**`owasp_report_save`** is **not** remediation. It persists **report output** to a path **provided by the client**. The **scanned repository tree** MUST remain unchanged by scan logic. Split the advisory scenario into **scan-only** vs **explicit save**.

### D4 - Tool docstrings

Each tool docstring SHOULD be 2–4 sentences: **what** it returns, **when** to use it, **one** contrast with the other tools. No Cursor-specific instructions; phrases like "MCP client" are fine.

### D5 - README layout

Add **Which tool to use** as a bullet list: **`owasp_scan`** (structured data), **`owasp_report`** (Markdown with links for reading in chat), **`owasp_report_save`** (same Markdown written to disk + small JSON). Cross-link to **`mcp.json`** reload after upgrades.

## Risks / Trade-offs

| Risk | Mitigation |
|------|------------|
| Over-long docstrings clog UI | Keep under ~120 words per tool; prioritize decision rules. |
| Normative "SHALL use owasp_report for links" confuses JSON-only workflows | Frame as Markdown report with links requires **owasp_report**; **owasp_scan** remains valid for automation. |

## Migration Plan

- Documentation and spec only; users **reload MCP** after pulling changes (already documented elsewhere).

## Open Questions

- Optional **patch** product version bump for "docs release" only - **deferred** (default no bump in this change).
