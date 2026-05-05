## Why

Solo users rely on **Cursor (and similar MCP hosts)** to pick the right tool. Today the **canonical spec** still reads like **two** MCP tools in the opening requirement, **`## Purpose` is a `TBD` placeholder**, and **`No silent remediation`** can be read as disallowing **`owasp_report_save`** entirely. That hurts **trust** (spec vs behavior) and **agent UX** (wrong tool = JSON summaries without Markdown links, or confusion about disk writes). **PyPI** distribution is **out of scope** for this change.

## What Changes

- Replace **`## Purpose`** in **`openspec/specs/owasp-top10-mcp/spec.md`** with concrete prose (solo / agent audience, stdio MCP, static scan scope, local operation without requiring PyPI).
- **MODIFIED** requirements in the same spec: **Local MCP server exposes…** (three tools), **No silent remediation** (explicit exception for client-directed **`owasp_report_save`**), **Client-agnostic MCP surface** (each tool description states **when to use** it vs the others), **Markdown report tool** (clarify that **navigable Markdown** comes from **`owasp_report`**, not **`owasp_scan`** alone).
- **README:** add a short **Which tool to use** section aligned with the spec; reinforce **reload MCP after local install** where relevant.
- **`server.py`:** expand MCP **tool docstrings** so schema descriptions match the README and spec (portable wording, no Cursor-only fields).
- **No** new MCP tools, **no** rulepack or **`schema_version`** changes, **no** product semver bump unless maintainers chose a doc-only patch later (default: **stay on current** product version).

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `owasp-top10-mcp`: specification preamble and selected requirements; documentation and tool descriptions for trustworthy, agent-friendly tool choice.

## Impact

- **`openspec/specs/owasp-top10-mcp/spec.md`** (via delta merged at archive).
- **`README.md`**, **`owasp_top10_mcp/server.py`**.
- **Tests:** optional lightweight check that tool descriptions remain non-empty and mention key terms (or manual review only per tasks).
