## Why

Human-readable **`owasp_report`** output should make it easy to open **authoritative documentation** while triaging findings. Today the report links each finding to the correct **OWASP Top 10:2025 category** page; readers still lack a compact **MITRE CWE** jump-off and a single place that lists **all** `references` URLs as **clickable** Markdown links. Aligning the patch release **v1.0.1** with this improvement keeps expectations clear for consumers and agents.

## What Changes

- Bump **product version** to **1.0.1** (PyPI/package metadata and scan metadata `product_version`). **Rulepack** stays **`2025.1`** unless finding JSON schema changes (this change is presentation + CWE linking only).
- **Markdown report** (`render_markdown` / `owasp_report`): for each finding, emit **clickable CWE links** for every id in `cwe` using the canonical MITRE URL pattern. Emit a **Further reading** (or equivalent) subsection that lists **each** entry in the finding's `references` array as a Markdown link `[label](url)` (dedupe redundant lines if the same URL appears twice). **Retain** existing **Category link** `[OWASP Ax](top10-url)` behavior in summary and per finding.
- **JSON** (`owasp_scan`): unchanged schema **`schema_version` `1.0`**; **`cwe`** remains optional on findings; no new required fields for v1.0.1.
- **Exploration carry-over (in scope):** richer "more information" in the **report body** via CWE + full `references` listing. **Out of scope for v1.0.1:** curated OWASP Cheat Sheet links per `rule_id`, server-side **save-to-disk**, PDF.
- No **BREAKING** MCP tool signatures.

## Capabilities

### New Capabilities

- `owasp-report-doc-links`: Markdown report enhancements - CWE deep links, full `references` as clickable Markdown, preserving existing OWASP Top 10 category links; version **1.0.1** bump.

### Modified Capabilities

- None (no archived `openspec/specs/` baselines in-repo yet).

## Impact

- **`owasp_top10_mcp/scan/markdown.py`** - primary implementation.
- **`owasp_top10_mcp/__init__.py`**, **`pyproject.toml`**, **`README.md`** - version strings where product version is stated.
- **Tests** - extend Markdown snapshot or string assertions for CWE and references sections.
- **Deferred change** (`owasp-report-save-to-disk` or similar): optional file save with user-confirmed path remains a **separate** future OpenSpec change.
