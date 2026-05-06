## Context

The walker assigns **tier-1** vs **best_effort** via `TIER1_EXT` and `run_rules_on_file` routes **tier1** non-Python files with **Vue/Svelte/HTML/JS** suffixes into **`analyze_lines_js_tier1`**. **`.astro`** components (Astro’s SFC format) are not tier-1 today, so Astro-heavy repos miss the same heuristics used for **`.vue`** and **`.svelte`**.

## Goals / Non-Goals

**Goals:**

- Include **`.astro`** in the **tier-1** file set and apply **existing** JS tier-1 rules (line-oriented) without introducing an Astro parser or subprocess.
- Prove behavior with a **fixture** that emits at least one finding from an **existing** rule when scanning a **`.astro`** file.
- Keep **schema_version**, MCP surface, and **default scan caps** unchanged.

**Non-Goals:**

- **Astro compiler** / AST integration, MDX, or new **OWASP categories**.
- **New rule families** beyond what existing **`analyze_lines_js_tier1`** already covers (optional follow-up change).
- **Java/Go** or deeper **IaC** upgrades (remain best-effort / context as today).

## Decisions

### D1 - Full-file line analysis for `.astro`

- **Choice:** Pass the **entire decoded file text** through **`analyze_lines_js_tier1`** (same as other SFCs), including YAML **frontmatter** between `---` fences and the **HTML-like template** and **`script`** regions.
- **Rationale:** Matches current approach for **`.vue`** (no SFC parser); minimal code churn. Frontmatter is usually short; false positives can be tuned later.
- **Alternative (deferred):** Strip the first `---` … `---` block before running rules if noise dominates in real repos.

### D2 - Walker extension

- **Choice:** Add **`.astro`** to **`TIER1_EXT`** in **`walker.py`** so eligibility returns **`tier1`** (same as `.tsx`, `.vue`, `.svelte`).
- **Rationale:** Single source of truth for “deep web” extensions.

### D3 - Rule routing

- **Choice:** Extend the **`tier1`** suffix tuple in **`run_rules_on_file`** to include **`.astro`**, invoking **`analyze_lines_js_tier1`**.
- **Rationale:** Reuses proven DOM/XSS/eval-style heuristics; no new `rule_id` required for a minimal acceptance test if **`target=_blank`** without **`rel`** appears in template markup.

### D4 - Cheat sheet map

- **Choice:** **No** new **`rule_id`** entries required for acceptance. If future rules add Astro-specific IDs, extend **`cheat_sheets.py`** in the same PR or a follow-up.
- **Rationale:** This change is **surface + routing** only.

### D5 - Versioning

- **Choice:** Ship **product 1.0.5** with this change so **`scan.product_version`**, release notes, and the canonical spec stay aligned.
- **Rationale:** User-visible scan behavior improves for Astro repos; patch semver communicates that in reports and MCP confirmation payloads.

## Risks / Trade-offs

| Risk | Mitigation |
|------|------------|
| Frontmatter triggers misleading hits | Monitor; consider D1 alternative in a small follow-up if needed. |
| Astro template syntax confuses regex heuristics | Same class of risk as `.vue`; accept for v1 of this change. |
| Larger tier-1 corpus → more files under caps | unchanged caps; truncation behavior already documented. |

## Migration Plan

Ship as implementation-only (walker + rules + tests). Existing clients **reload MCP** after upgrade per README; no config migration.

## Open Questions

- None blocking; optional **MDX** tier-1 is a separate proposal if demand appears.
