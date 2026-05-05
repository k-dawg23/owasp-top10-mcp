## Why

Readers triage from **category links** and **CWE** already; **OWASP Cheat Sheet Series** pages are the next practical jump-off for solo developers. A **small, curated, bundled map** from **`rule_id`** (with **category fallback**) keeps v1 **static and offline** while improving report depth without claiming new detection power.

This release ships as **product v1.0.4** (PyPI **out of scope**).

## What Changes

- Bump **product version** to **1.0.4** (`pyproject.toml`, **`__version__`**, **`scan.product_version`**).
- Add a **bundled** cheat sheet map (**implementation-defined** table file or module under `owasp_top10_mcp/`), keyed by **`rule_id`**, with optional **per-OWASP-id** fallback URLs when a rule is unmapped.
- **`render_markdown`**: optional **`#### Cheat sheet`** subsection per finding when at least one URL applies; **Markdown links** with stable titles; **omit** when empty (no placeholder).
- **`schema_version`** unchanged; **no new required** JSON fields (optional **`cheat_sheets`** array on findings MAY be added in implementation if desired for agent parity; default in **design** is **Markdown-first** to limit scope).
- **README** and maintainer note: map is **hand-curated**, links may need periodic review; **no runtime fetch**.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `owasp-top10-mcp`: bundled cheat sheet map + Markdown rendering; **product version 1.0.4**.

## Impact

- **`owasp_top10_mcp/scan/markdown.py`**, new map module or data file, tests, README, `pyproject.toml` / `__init__.py` / `uv.lock` as today.
- **`openspec/specs/owasp-top10-mcp/spec.md`** updated via delta at archive.

### Ordering note

Pending changes may advance semver (e.g. **1.0.3** for JSON save). When **archiving** this delta, apply **`REMOVED` / `ADDED`** product version blocks against whatever **single** product-version requirement title exists in the main spec (remove duplicates).
