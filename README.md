# owasp-top10-mcp

Local **MCP** server (stdio) for **static** repository scans mapped to **OWASP Top 10:2025**. **Product v1.0.5**, **rulepack 2025.1**.

- **Repository:** [github.com/k-dawg23/owasp-top10-mcp](https://github.com/k-dawg23/owasp-top10-mcp)  
- **License:** [MIT](LICENSE)

Design and specs: `openspec/changes/owasp-top10-mcp/`.

## Requirements

- **Python 3.11+**
- **[uv](https://github.com/astral-sh/uv)** (recommended for installs), or use the project venv only

## Install

```bash
cd /path/to/OWASP-Top_10
uv sync --extra dev
```

This creates `.venv` and installs the `owasp-top10-mcp` package (setuptools editable install).

## When there is a new version

The **Product** line in JSON and Markdown reports comes from whatever code the **MCP server process** actually imports (`scan.product_version` is derived from `owasp_top10_mcp.__version__`). If scans still show an old product version, the client is not running the updated install.

### If you use Cursor MCP from a local clone

1. **Update the repo** (pull, checkout tag, or copy in the new tree).
2. **Reinstall into the same venv** that `mcp.json` points at (from the project root):
   ```bash
   uv sync --extra dev
   ```
   or, equivalently:
   ```bash
   .venv/bin/pip install -e .
   ```
3. **Confirm** the interpreter sees the expected version:
   ```bash
   .venv/bin/python -c "import owasp_top10_mcp; print(owasp_top10_mcp.__version__)"
   ```
4. **Reload MCP servers** in Cursor or **restart Cursor** so the `owasp-top10` server picks up the new package.

Keep **`mcp.json`** paths **absolute** and aligned with that venv (see below). If you use `uv run --directory ...`, ensure `--directory` is this project root after the update.

### If you install from PyPI

Run **`pip install -U owasp-top10-mcp`** (or `uv add 'owasp-top10-mcp==x.y.z'`) in the environment your MCP `command` uses, then restart the MCP server.

### Maintainers: bumping the product version

1. Set **`__version__`** in `owasp_top10_mcp/__init__.py` to the new release (e.g. `1.0.5`).
2. Set **`version`** in `pyproject.toml` under `[project]` to the **same** string.
3. Update the **lead sentence** of this README if it states the version explicitly.
4. Add a bullet under **Release notes** (below).
5. For a published release: commit, tag `vx.y.z`, build/push wheels to PyPI as you usually do.

Rulepack changes use **`RULEPACK_VERSION`** in `owasp_top10_mcp/__init__.py` and are independent of the product semver; bump that only when bundled rule content changes per your release policy.

## How to run a scan

### Which tool to use

Pick one primary tool per goal (each runs the same static scan engine; parameters match aside from save-specific options):

- **`owasp_scan`** — Return the **JSON** findings envelope (best for automation, filtering, and tooling). No Markdown body and no file write.
- **`owasp_report`** — Return the **Markdown** report string (best for reading in chat: OWASP, CWE, cheat sheet, and other links as implemented).
- **`owasp_report_save`** — Write that **Markdown** to an **absolute** `output_path`; the MCP result is a **small JSON** confirmation, not the full report.
- **`owasp_scan_save`** — Write the same **JSON** envelope **`owasp_scan`** would return to an **absolute** `output_path`; confirmation JSON only in the tool result.

After you **`git pull`** or change versions, **reload MCP** in your host or restart it so the server process loads the updated package (see **When there is a new version**).

### Option A — Cursor (or any MCP client)

1. Register the server in **`~/.cursor/mcp.json`** (see below), then reload MCP or restart Cursor.
2. In chat, ask your agent to call **`owasp_scan`**, **`owasp_report`**, **`owasp_report_save`**, or **`owasp_scan_save`** with an **absolute `repo_root`** path. For the **`*_save`** tools, use an **absolute `output_path`** as well.

**`owasp_scan`** returns structured **JSON** (best for agents). **`owasp_scan_save`** runs the **same scan once** and writes that **exact JSON envelope** to disk (UTF-8, `indent=2`, `ensure_ascii=False`, trailing newline) — useful for CI artifacts, tickets, or archival without copy-pasting tool output. Prefer **`.json`** in `output_path` names client-side (e.g. `owasp-scan-<ISO8601>.json`); the server does not choose filenames.

**Markdown reports** (**`owasp_report`**, **`owasp_report_save`**) include a per-finding **`#### Cheat sheet`** subsection when a **bundled, curated** map resolves to OWASP Cheat Sheet Series links (by **`rule_id`**, with a **category fallback** for A01–A10). Links are **offline** (no fetch at scan time) and may need **occasional maintainer review** if URLs move. **PyPI** publishing is not required to use this project from a clone.

**`owasp_report`** takes the **same arguments** as **`owasp_scan`** and returns **Markdown** for reading or saving. Reports include **MITRE CWE** links (when rules emit `cwe` ids) and a **Further reading** list for supplementary `references` URLs (the primary OWASP category link stays on its own line; duplicate category URLs are not repeated there).

**`owasp_report_save`** runs the **same scan** as **`owasp_report`** and writes Markdown to disk. Parameters are the same as **`owasp_report`** plus:

- **`output_path`** (required): absolute path to the `.md` file to write. Parent directories are created if missing. `~` is expanded.
- **`overwrite`** (optional, default `false`): set `true` to replace an existing file.

The tool returns a **small JSON object** (`path`, `bytes_written`, `truncated`, `rulepack_version`, `product_version`), not the full report body. Confirm the path with the user before writing.

**`owasp_scan_save`** mirrors **`owasp_report_save`** but writes the **JSON envelope** (same object **`owasp_scan`** would return): same scan parameters plus **`output_path`** and **`overwrite`**. File encoding is UTF-8 JSON with **`indent=2`**, **`ensure_ascii=False`**, and a single trailing newline. The tool result is a compact dict: **`path`**, **`bytes_written`**, **`finding_count`**, **`truncated`**, **`rulepack_version`**, **`product_version`** (not the full scan).

**Filename convention (clients):** the server does not pick names. Use **`.md`** / **`.json`** in `output_path` as appropriate, e.g. `owasp-report-<ISO8601>-<short-id>.md` or `owasp-scan-<ISO8601>.json`.

Do **not** expect `owasp-top10-mcp` alone to print a scan to the terminal: that command starts the **MCP server** and waits on stdio for the client.

### Option B — One-off scan from the shell (no MCP)

JSON to stdout:

```bash
cd /path/to/OWASP-Top_10
uv run python -c "
from pathlib import Path
import json
from owasp_top10_mcp.scan.engine import run_scan

repo = Path('/absolute/path/to/target/repo').resolve()
print(json.dumps(run_scan(str(repo), profile='human_full'), indent=2))
"
```

Markdown report to stdout:

```bash
uv run python -c "
from pathlib import Path
from owasp_top10_mcp.scan.engine import run_scan
from owasp_top10_mcp.scan.markdown import render_markdown

repo = str(Path('/absolute/path/to/target/repo').resolve())
print(render_markdown(run_scan(repo, profile='human_full')))
"
```

### Tool / API parameters

| Parameter | Required | Notes |
|-----------|----------|--------|
| `repo_root` | yes | Absolute path to repository root. Must exist. |
| `profile` | no | `agent_quick` (default; higher severity floor, tighter caps) or `human_full`. |
| `categories` | no | e.g. `["A05","A04"]` for OWASP 2025 **A01–A10** only; omit for all. |
| `max_files`, `max_bytes_per_file`, `max_total_bytes`, `time_budget_ms`, `severity_floor` | no | Override defaults from the OpenSpec design (caps / truncation). |

**`owasp_report_save`**, **`owasp_scan_save`**: each requires `output_path` (absolute) and optional `overwrite` (default `false`). Large repos can produce large JSON files on disk (same caps as **`owasp_scan`**).

Invalid `repo_root` or unknown category codes raise **ValueError** with a short message. Relative **`output_path`** raises **ValueError**; existing file with **`overwrite`** false raises **FileExistsError**.

## Cursor MCP configuration (`~/.cursor/mcp.json`)

Using the project **venv** avoids depending on `uv` or `python` being on Cursor’s GUI **PATH**:

```json
{
  "mcpServers": {
    "owasp-top10": {
      "command": "/absolute/path/to/OWASP-Top_10/.venv/bin/python",
      "args": ["-m", "owasp_top10_mcp"]
    }
  }
}
```

Alternative (if `uv` is available to the Cursor process):

```json
"owasp-top10": {
  "command": "uv",
  "args": ["run", "--directory", "/absolute/path/to/OWASP-Top_10", "owasp-top10-mcp"]
}
```

After editing **`mcp.json`**, reload MCP servers or restart Cursor.

## Release notes

- **v1.0.5** - **Astro** **`.astro`** files use **tier-1** scan depth (same JavaScript tier-1 rule pass as **`.vue`** / **`.svelte`** / HTML); README adds **Scan surface and depth**; OpenSpec change **`astro-tier1-scan`** (for archive workflow).
- **v1.0.4** - Markdown reports add **curated OWASP Cheat Sheet Series** links (`#### Cheat sheet` per finding); bundled static map keyed by **`rule_id`** with A01–A10 fallback; no network I/O for link resolution.
- **v1.0.3** - MCP tool **`owasp_scan_save`**: write the **JSON scan envelope** to an **absolute** `output_path` (optional **`overwrite`**); returns confirmation including **`finding_count`**, not the full payload.
- **v1.0.2** - MCP tool **`owasp_report_save`**: write the Markdown report to an **absolute** `output_path` (optional **`overwrite`**); returns JSON confirmation, not the full report body.
- **v1.0.1** - Markdown reports add **CWE** links (`cwe.mitre.org`) and **Further reading** from `references`, omitting URLs that duplicate the finding's **Category link** after URL normalization.

## v1 limitations

- **Static only** — no DAST, no bundled subprocess scanners (`npm audit`, Semgrep, …), **no** network OSV/CVE correlation.
- **Advisory** — the server does not modify the repo; remediation is via your own review or agent-proposed patches.
- **PDF** — not generated; use Markdown and convert externally if you need PDF.

## Scan surface and depth (v1)

The walker skips common vendor and build directories (e.g. **`node_modules`**, **`.git`**) and honors **`.gitignore`**. Eligible paths use a **tier** flag:

- **Tier-1** (deeper, line-based rules for Python and typical web stacks): **`.py`**; **`.js`**, **`.jsx`**, **`.ts`**, **`.tsx`**, **`.mjs`**, **`.cjs`**; **`.vue`**, **`.svelte`**, **`.astro`**; **`.html`**, **`.htm`**. These files run the same **JavaScript/TypeScript tier-1** analyzer as other SFC-style extensions (Astro components are treated like Vue/Svelte for that pass—no Astro compiler; full-file text including frontmatter).
- **Context / manifests:** e.g. **Dockerfile**, **docker-compose**, **`package.json`**, lockfiles, **`requirements.txt`**, selected **YAML** (incl. GitHub workflows, K8s dirs), **Terraform**—targeted or generic checks.
- **Best-effort:** other configured extensions (e.g. **`.go`**, **`.java`**, many **`.json`** outside allowlisted names) get lighter generic rules only.

For the exact allowlists and blocked dirs, see **`owasp_top10_mcp/scan/walker.py`**. Caps (`max_files`, `time_budget_ms`, …) still apply; large repos may truncate per scan metadata.

## Roadmap (v2 ideas)

- Optional **subprocess** scanners and **OSV/advisory** mode behind explicit flags (schema bump).
- Optional **per-category** MCP façades (thin wrappers over the same engine).

## Tests

```bash
uv run pytest
```

## Default performance profiles

**`agent_quick`** is tuned so scans usually finish in reasonable time on typical solo repos (on the order of tens of thousands of lines of app code, excluding `node_modules`). Use **`human_full`** or raise **`max_files`** / **`time_budget_ms`** when you intentionally want deeper or longer runs.
