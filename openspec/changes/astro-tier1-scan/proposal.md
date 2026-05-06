## Why

Several real-world repos in this maintainer's workspace use **Astro** for storefronts and full apps, but **`.astro` files are not in the tier-1 corpus** today, so they only receive **best-effort** rules (or none) despite containing the same **HTML/JS/TS-style** sinks as **`.vue` / `.svelte`**. That weakens **OWASP Top 10–oriented** static signal for a growing share of **web/app** code without adding subprocess scanners or new product semver by itself.

## What Changes

- Treat **`.astro`** as **tier-1** in the file walker (same eligibility tier as `.vue`, `.svelte`, `.tsx`, etc.).
- Route **`.astro`** files through the existing **JavaScript/TypeScript tier-1** rule path (`analyze_lines_js_tier1` or equivalent) so current DOM/XSS-oriented checks apply to Astro **component frontmatter + template + client scripts** as **line-oriented** text (no Astro compiler integration in v1 of this change).
- **Optional design detail** (see `design.md`): whether to strip YAML frontmatter delimiters for rule application to reduce noise; default = **full-file** unless implementation proves too noisy.
- Add **tests** with a minimal **`.astro`** fixture that triggers at least one **existing** tier-1 rule (e.g. `target=_blank` without `rel` or a known JS sink pattern).
- **Modified capability** `owasp-top10-mcp`: spec delta clarifies that **Astro components** (`.astro`) are included in **tier-1 language depth** alongside other SFC-style web files **where implemented**.
- **Product version** **1.0.5** (patch): documents Astro tier-1 + README scan surface in release notes.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `owasp-top10-mcp`: **Language depth / scan surface** — **`.astro`** MUST be discovered as **tier-1** when present under the repository root (subject to existing caps, gitignore, and `BLOCKED_DIRS`), and MUST be analyzed with **tier-1 web/js** depth (same rule family as other tier-1 JS/TS/HTML SFC extensions documented in implementation).
- `owasp-top10-mcp`: **Product version** requirement updated to **1.0.5** (shipped with this change).

## Impact

- **`owasp_top10_mcp/scan/walker.py`**: add `.astro` to **`TIER1_EXT`** (or equivalent eligibility returning tier `tier1`).
- **`owasp_top10_mcp/scan/rules_builtin.py`**: include `.astro` in the **`tier1`** branch that calls **`analyze_lines_js_tier1`** (mirror `.vue` / `.svelte` list).
- **`tests/`**: new or extended fixture under `tests/fixtures/` and assertions in **`test_scan.py`** (or adjacent).
- **`openspec/specs/owasp-top10-mcp/spec.md`**: language depth + product version **1.0.5** (merged at archive or applied with implementation).
- **`README.md`**: **Scan surface and depth** section; **v1.0.5** release note.
- **No** MCP tool or **`schema_version`** change.
