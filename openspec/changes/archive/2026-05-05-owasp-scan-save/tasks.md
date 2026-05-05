## 1. Version

- [x] 1.1 Bump **product version** to **1.0.3** in `pyproject.toml`, `owasp_top10_mcp/__init__.py`, and **`uv.lock`** if it pins the workspace package version.

## 2. JSON save helper and MCP tool

- [x] 2.1 Add **`save_scan_json`** (or equivalent) that validates **`output_path`** (absolute, **`~`** expanded), respects **`overwrite`**, serializes the scan dict with **`json.dumps(..., indent=2, ensure_ascii=False)`** plus a trailing newline, and reuses **`write_utf8_file_atomic`** from **`report_save.py`** (or refactor shared path checks if needed).
- [x] 2.2 Register **`owasp_scan_save`** on **`FastMCP`** with the same parameters as **`owasp_scan`** plus **`output_path`** and **`overwrite`**; return confirmation **`dict`** per **`design.md` D3** (include **`finding_count`**).

## 3. Documentation

- [x] 3.1 Update **README**: document **`owasp_scan_save`**, suggest **`.json`** filenames client-side, cross-link with **`owasp_report_save`**; add release note for **v1.0.3**.

## 4. Tests

- [x] 4.1 **`tmp_path`**: saved file parses as JSON and matches **`run_scan`** result for same args under the declared **`json.dumps`** policy (byte-for-byte or `json.loads` equality).
- [x] 4.2 Relative **`output_path`** raises; existing file + **`overwrite`** false preserves content; **`overwrite`** true replaces.
- [x] 4.3 Response includes **`path`**, **`bytes_written`**, **`finding_count`**, **`truncated`**, **`rulepack_version`**, **`product_version`**; **`product_version`** in **`owasp_scan`** is **1.0.3**.
