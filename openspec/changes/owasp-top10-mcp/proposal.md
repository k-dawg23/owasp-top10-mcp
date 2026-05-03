## Why

Solo developers using AI coding agents (Cursor, Codex, local LLMs via llama.cpp, Ollama, LM Studio) need a **consistent, machine-readable** way to scan repositories for issues aligned with **OWASP Top 10:2025**, plus an optional **human-readable Markdown report**. A local MCP server keeps analysis **in-repo and static for v1**, integrates with those agents’ tool protocols, and avoids pretending to be a full pentest while still improving triage and remediation.

## What Changes

- Introduce **owasp-top10-mcp v1.0.0**: a **local MCP server** (stdio) that performs **static repository analysis only** in v1—**no subprocess** scanners (e.g. Semgrep, `npm audit`) and **no network** (no OSV/CVE correlation) until a later version.
- Expose a **primary scan tool** (`owasp_scan` or equivalent) with optional filtering by OWASP category (A01–A10:2025), scan **profiles** (`agent_quick`, `human_full`), and **performance caps** so runs complete predictably on large trees.
- Scan surface includes **application source** plus **high-value repo context**: `Dockerfile*` / Compose, CI workflow files, **lockfiles** and package manifests, and **common IaC** where feasible (scope of file globs per design).
- **Tier-1 depth** for **Python** and **JavaScript/TypeScript**; **best-effort** patterns for other languages.
- Every run emits **`schema_version` `1.0`** findings JSON, **rulepack version** (e.g. `2025.1`), scan metadata (truncation, caps, timing), and fields for **suggest-and-fix policy** (`patch_candidate`, `fix_class`, `behavior_change`, `blast_radius`, `confidence`) with **no silent application** of fixes by the server.
- **`owasp_report`** MCP tool (separate from **`owasp_scan`**) emits a **Markdown report** for the user (summary, grouped findings, limitations) using the **same scan parameters** as **`owasp_scan`**. **`owasp_scan`** returns **JSON only**. **PDF** is explicitly deferred.
- **Per-category OWASP façade tools** (ten thin MCP tools) are **not** required for v1; the unified scan remains the default; thin aliases may be added later without changing the core schema.

## Capabilities

### New Capabilities

- `owasp-top10-mcp`: Local MCP server, static scan engine, OWASP Top 10:2025-aligned findings, JSON + Markdown outputs, performance and honesty under caps, rulepack versioning, and remediation policy fields for agent-assisted review.

### Modified Capabilities

- None (no existing `openspec/specs/` baselines in this repository).

## Impact

- **New codebase** (implementation language per `design.md`; default assumption **Python** with `uv`/venv-friendly entrypoint unless implementation chooses otherwise).
- **New MCP package / CLI** documented for solo install (clone + run; optional `uv`/`pipx` later).
- **Cursor / Codex / other MCP clients**: `mcp.json` (or equivalent) configuration pointing at the server command.
- **No runtime dependency** on hosted services for core v1 scanning; local LLM hosts unchanged—they consume tool results as structured JSON.

## Non-goals (v1 and unless explicitly re-scoped later)

This effort does not include dynamic or black-box testing (DAST), runtime instrumentation, penetration testing, proof-of-concept exploitation, red-team workflows, or assurance that findings are exploitable in deployment. It does not replace a full secure SDLC—threat modeling, security requirements, code review gates, ticketing, compliance programs, vendor risk, or organizational processes are out of scope. The scanner is a static, repo-oriented aid for prioritization and remediation guidance only; any “fix” path is advisory and human-reviewed, not a guarantee of safety or completeness. **CVE/advisory correlation** and **external CLI scanners** are deferred to a future version.

## Success criteria

- The server runs **locally over MCP stdio** with no required hosted dependency for core v1 scanning.
- On a **representative private repo** (order-of **50k–150k LOC** of application code for Python + JavaScript, excluding `node_modules` and build artifacts), default **`agent_quick`** completes in **under about two minutes** on a normal laptop, or exits with explicit truncation metadata.
- Each scan produces **structured JSON findings** (for agents) and **optional Markdown** (for humans), including **rulepack version** and **honest partial-coverage** flags when caps apply.
- **No silent apply**: the server never writes patches; `patch_candidate` follows the narrow v1 definition in `design.md`.
