## 1. Bootstrap and documentation

- [x] 1.1 Initialize Python project (`pyproject.toml`, app package layout, `uv`/`venv` instructions), pin **Python 3.11+**, and add PyPI dependency **`mcp`** from the **[official MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)** with a pinned version (track SDK **v1.x** per upstream).
- [x] 1.2 Add **README** with Cursor/Codex-style **MCP stdio** config snippet, clone-and-run path, and **offline v1** limitations.
- [x] 1.3 Record **product version v1.0.0** and **rulepack `2025.1`** in project metadata and scan output.

## 2. MCP server shell

- [x] 2.1 Integrate **MCP Python SDK** (or equivalent) with **stdio** transport and healthful error messages for bad `repo_root`.
- [x] 2.2 Implement **`owasp_scan`** returning **only** the JSON findings envelope (`repo_root`, optional `categories[]`, `profile`, optional cap overrides).
- [x] 2.3 Implement **`owasp_report`** with the **same parameters** as **`owasp_scan`**, shared scan engine, **Markdown-only** tool result; document sort order for parity with JSON.
- [x] 2.4 Validate inputs (existing path, category codes A01–A10) and return actionable MCP errors for both tools.

## 3. Repository walking and caps

- [x] 3.1 Implement repo walking with **respect for `.gitignore`** (or documented default excludes), plus hard excludes (`node_modules`, `.git`, common `dist/build/coverage`).
- [x] 3.2 Apply **profile defaults** for `max_files`, `max_bytes_per_file`, `max_total_bytes`, `severity_floor`, `time_budget_ms` per `design.md`.
- [x] 3.3 Emit **`truncated`** and **`truncation_reasons[]`** when any cap or time budget triggers early stop.

## 4. Rule engine and OWASP mapping

- [x] 4.1 Define **`rulepack_version`** and pluggable **rule modules** tagged by OWASP **A01–A10:2025**.
- [x] 4.2 Implement **tier-1** heuristics/patterns for **Python** and **JS/TS**; **best-effort** pass for other extensions.
- [x] 4.3 Implement **repo-context** parsers/checks for `Dockerfile`, Compose, CI YAML, manifests, lockfiles, and **IaC globs** in **`design.md` D10**.
- [x] 4.4 Ensure **A03** findings never claim CVEs without advisory mode; add **`limitations`** including `no_cve_correlation_in_v1` where applicable.

## 5. Findings model and invariants

- [x] 5.1 Implement JSON envelope **`schema_version` `1.0`**, `scan` metadata, `findings[]` per spec.
- [x] 5.2 Enforce **`patch_candidate`** invariants (`mechanical` + `behavior_change` false when true; `sensitive` forces false).
- [x] 5.3 Maintain **`patch_candidate_allowlist`** (start empty or minimal); default `patch_candidate` false for all other rules.
- [x] 5.4 Implement finding **`id`** as **SHA-256** (lowercase hex) of the **canonical key** per **`design.md` D2b** (not UUIDs).

## 6. Markdown report

- [x] 6.1 Render Markdown with header (**rulepack**, profile, timing, truncation, limits).
- [x] 6.2 Group or sort findings by **severity** and **OWASP id**; include deep links to **https://owasp.org/Top10/2025/** category pages.
- [x] 6.3 Document that **PDF** is out of scope for v1 (optional external render only).

## 7. Testing and fixtures

- [x] 7.1 Add **fixture repos** (tiny samples) covering at least one positive case per **tier-1** category slice and truncation behavior.
- [x] 7.2 Add unit/integration tests for JSON schema shape, truncation flags, and category filtering.
- [x] 7.3 Dogfood on a **50k–150k LOC**-scale private sample (or synthetic tree) and tune default caps documented in `design.md`.

## 8. v2 placeholders (no implementation required in v1)

- [x] 8.1 Document roadmap hooks for **subprocess scanners** and **OSV/advisory** mode with explicit **opt-in** and schema bumps.
- [x] 8.2 Note optional future **ten thin MCP tools** as aliases to `owasp_scan` with fixed `categories`.
