# owasp-top10-mcp

Local **MCP** server (stdio) for **static** repository scans mapped to **OWASP Top 10:2025**. **Product v1.0.1**, **rulepack 2025.1**.

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

1. Set **`__version__`** in `owasp_top10_mcp/__init__.py` to the new release (e.g. `1.0.2`).
2. Set **`version`** in `pyproject.toml` under `[project]` to the **same** string.
3. Update the **lead sentence** of this README if it states the version explicitly.
4. Add a bullet under **Release notes** (below).
5. For a published release: commit, tag `vx.y.z`, build/push wheels to PyPI as you usually do.

Rulepack changes use **`RULEPACK_VERSION`** in `owasp_top10_mcp/__init__.py` and are independent of the product semver; bump that only when bundled rule content changes per your release policy.

## How to run a scan

### Option A — Cursor (or any MCP client)

1. Register the server in **`~/.cursor/mcp.json`** (see below), then reload MCP or restart Cursor.
2. In chat, ask your agent to call **`owasp_scan`** or **`owasp_report`** with an **absolute `repo_root`** path.

**`owasp_scan`** returns structured **JSON** (best for agents). **`owasp_report`** takes the **same arguments** and returns **Markdown** for reading or saving. Reports include **MITRE CWE** links (when rules emit `cwe` ids) and a **Further reading** list for supplementary `references` URLs (the primary OWASP category link stays on its own line; duplicate category URLs are not repeated there).

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

Invalid `repo_root` or unknown category codes raise **ValueError** with a short message.

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

- **v1.0.1** - Markdown reports add **CWE** links (`cwe.mitre.org`) and **Further reading** from `references`, omitting URLs that duplicate the finding's **Category link** after URL normalization.

## v1 limitations

- **Static only** — no DAST, no bundled subprocess scanners (`npm audit`, Semgrep, …), **no** network OSV/CVE correlation.
- **Advisory** — the server does not modify the repo; remediation is via your own review or agent-proposed patches.
- **PDF** — not generated; use Markdown and convert externally if you need PDF.

## Roadmap (v2 ideas)

- Optional **subprocess** scanners and **OSV/advisory** mode behind explicit flags (schema bump).
- Optional **per-category** MCP façades (thin wrappers over the same engine).

## Tests

```bash
uv run pytest
```

## Default performance profiles

**`agent_quick`** is tuned so scans usually finish in reasonable time on typical solo repos (on the order of tens of thousands of lines of app code, excluding `node_modules`). Use **`human_full`** or raise **`max_files`** / **`time_budget_ms`** when you intentionally want deeper or longer runs.
