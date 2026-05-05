## Why

Solo users and agents often want a **durable JSON** scan result (CI artifacts, tickets, offline archival) without copy-pasting **`owasp_scan`** output. **`owasp_report_save`** already covers **Markdown** to disk; **Proposal 2** adds symmetry: **`owasp_scan_save`** writes the **same findings envelope** that **`owasp_scan`** would return, with identical **path / overwrite** safety to the Markdown saver.

**OpenSpec change id:** `owasp-scan-save` (hyphenated; MCP tool name remains **`owasp_scan_save`**).

## What Changes

- Bump **product version** to **1.0.3** (`pyproject.toml`, `__version__`, `scan.product_version`).
- New MCP tool **`owasp_scan_save`**: same scan parameters as **`owasp_scan`**, plus **`output_path`** (absolute) and optional **`overwrite`** (default false). Runs **`run_scan`**, serializes the envelope to **UTF-8 JSON** (pretty-printed, **`ensure_ascii=False`** for readable Unicode), writes via **atomic replace** (same pattern as **`owasp_report_save`**).
- Tool returns a **small JSON-serializable dict** (e.g. **`path`**, **`bytes_written`**, **`truncated`**, **`finding_count`**, **`rulepack_version`**, **`product_version`**), not the full findings payload in the tool result.
- **README** documents when to use **`owasp_scan_save`** vs **`owasp_scan`** vs **`owasp_report_save`**.
- **Not in scope:** per-category MCP façade tools (thin wrappers); a separate change if still desired.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `owasp-top10-mcp`: **`owasp_scan_save`**, product **1.0.3**, JSON file write semantics aligned with **`owasp_report_save`**.

## Impact

- **`owasp_top10_mcp/report_save.py`** (or adjacent helper): JSON serialization + reuse **`write_utf8_file_atomic`**.
- **`owasp_top10_mcp/server.py`**: register **`owasp_scan_save`**.
- **`owasp_top10_mcp/__init__.py`**, **`pyproject.toml`**, **`README.md`**, **`uv.lock`** (if tracked).
- **`tests/test_scan.py`** (or new): parity file bytes vs `json.dumps(run_scan(...))`, relative path, overwrite, response keys.
- **`openspec/specs/owasp-top10-mcp/spec.md`**: via delta at archive.
