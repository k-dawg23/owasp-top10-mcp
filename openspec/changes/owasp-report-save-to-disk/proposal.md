## Why

Agents and users often want a **durable copy** of the Markdown report (for tickets, PRs, or audit folders) without manually pasting tool output. Exploration deferred **server-side save** to keep early releases small and to avoid writing files unless the caller supplies an explicit destination. **v1.0.2** adds an optional, explicit **save-to-disk** path while keeping **`owasp_report`** as the in-chat Markdown tool and **`owasp_scan`** JSON-only.

## What Changes

- Bump **product version** to **1.0.2** (`pyproject.toml`, package `__version__`, `scan.product_version`). **Rulepack** stays **`2025.1`**. **`schema_version`** stays **`1.0`** for `owasp_scan` JSON.
- Add a new MCP tool **`owasp_report_save`** that accepts the **same scan parameters** as **`owasp_report`** plus a **required absolute filesystem path** for the output `.md` file. It runs the **same scan engine**, renders Markdown identically to **`owasp_report`**, writes the bytes to disk, and returns a **small structured result** (e.g. path, size, scan metadata pointers) instead of the full report body.
- **Safety defaults:** require **absolute** `output_path`; default **no overwrite** (clear error if the file exists unless an explicit **overwrite** flag is set). Use **atomic replace** (write temp in destination directory, then rename) where the platform allows.
- **`owasp_report`** and **`owasp_scan`** behaviors remain **unchanged** for existing callers.
- No **BREAKING** changes to existing tool signatures.

## Capabilities

### New Capabilities

- None (behavior extends the existing shipped server spec).

### Modified Capabilities

- `owasp-top10-mcp`: Add **`owasp_report_save`** with explicit path semantics; bump **product version** to **1.0.2**; document that saving is **opt-in** and path is **caller-supplied** (exploration: agents should confirm the path with the user before invoking).

## Impact

- **`owasp_top10_mcp/server.py`** - register **`owasp_report_save`**; shared scan + `render_markdown`; thin file I/O helper (or small module under `owasp_top10_mcp/`).
- **`owasp_top10_mcp/__init__.py`**, **`pyproject.toml`**, **`README.md`** - version **1.0.2**; document suggested filenames (e.g. timestamp + short id) as **convention for clients**, not server-enforced.
- **Tests** - temp directory writes, content byte-for-byte parity with **`owasp_report`** for same scan inputs, relative path rejection, overwrite behavior.
