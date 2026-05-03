## 1. Version and docs

- [ ] 1.1 Bump **product version** to **1.0.2** in `pyproject.toml`, `owasp_top10_mcp/__init__.py`, and ensure `scan.product_version` reflects it.
- [ ] 1.2 Update **README**: describe **`owasp_report_save`**, absolute path rule, overwrite flag, suggested client-side filename pattern (timestamp + id) as optional convention.

## 2. File I/O helper

- [ ] 2.1 Add a small helper (e.g. under `owasp_top10_mcp/` or next to **`server.py`**) that validates **absolute** `output_path`, ensures parent dirs exist, writes **UTF-8** via temp file + **`os.replace`**, and honors **`overwrite`**.

## 3. MCP tool

- [ ] 3.1 Register **`owasp_report_save`** on **`FastMCP`** with the same scan parameters as **`owasp_report`** plus **`output_path`** and optional **`overwrite`** (default false).
- [ ] 3.2 Implement **`run_scan` + `render_markdown`**, then write; return structured **`dict`** per **`design.md` D4** and spec scenarios.

## 4. Testing

- [ ] 4.1 Test successful write under **`tmp_path`**, assert file bytes equal **`render_markdown(run_scan(...))`** encoded UTF-8.
- [ ] 4.2 Test relative **`output_path`** rejected.
- [ ] 4.3 Test existing file + **`overwrite`** false fails; **`overwrite`** true replaces content.
- [ ] 4.4 Test response includes **`path`**, **`bytes_written`**, **`truncated`**, **`rulepack_version`**, **`product_version`**.
