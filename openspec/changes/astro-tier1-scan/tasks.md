## 1. Eligibility

- [x] 1.1 Add **`.astro`** to **`TIER1_EXT`** in **`owasp_top10_mcp/scan/walker.py`** so eligible **`.astro`** files receive tier **`tier1`**.

## 2. Rules routing

- [x] 2.1 In **`owasp_top10_mcp/scan/rules_builtin.py`**, include **`.astro`** in the **`tier1`** suffix set that invokes **`analyze_lines_js_tier1`** (alongside **`.vue`**, **`.svelte`**, **`.html`**, etc.).

## 3. Tests

- [x] 3.1 Add a minimal **`tests/fixtures/`** tree (or single **`.astro`** file) containing markup that triggers an **existing** tier-1 rule (e.g. **`target=_blank`** without **`rel`** for **`owasp2025.a05.html.target-blank-no-opener`**, or another already-shipped rule).
- [x] 3.2 Assert **`run_scan`** (or walker + **`run_rules_on_file`**) reports at least one finding whose **`location.path`** ends with **`.astro`** when scanning that fixture with **`profile=\"human_full\"`** (or appropriate parameters).

## 4. Validation

- [x] 4.1 Run **`openspec validate astro-tier1-scan`** and **`pytest`** for the touched tests.
