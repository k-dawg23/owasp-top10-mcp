## 1. Version and constants

- [x] 1.1 Bump shipped **product version** to **1.0.6** (`pyproject.toml`, `owasp_top10_mcp/__init__.py` or equivalent, and any scan metadata source per existing pattern).
- [x] 1.2 Add **bundled** `OWASP API Security` **hub** URL constant and **API1**–**API10** → canonical doc URL map in `constants.py` (or sibling module), verified once against https://owasp.org/www-project-api-security/ during implementation (no network at scan time).
- [x] 1.3 Add `owasp_api_url(api_id: str) -> str` helper mirroring `owasp_top10_url` style where appropriate.

## 2. Finding schema and serialization

- [x] 2.1 Extend **`RawFinding`** with optional **`owasp_api_id`** (or structured `owasp_api`) validated to **`API1`..`API10`**; default **omit** from JSON when unset.
- [x] 2.2 Emit **`owasp_api`: `{ "year": 2023, "id": "…" }`** in **`to_final_dict`** only when set; confirm **`finding_id`** hash inputs **exclude** `owasp_api` and API-only reference strings.
- [x] 2.3 Merge **API category URL** (and optionally **hub**) into **`references`** when **`owasp_api`** is present, **deduping** by normalized URL against existing `references` and Top 10 category link.

## 3. Rulepack crosswalk

- [x] 3.1 Document and apply **rule_id → API1–API10** mappings for builtin rules where mapping is defensible (start with high-signal rules: authz/authn/injection/secrets/misconfiguration-related); leave unmapped rules unchanged.
- [x] 3.2 For engine-level reminders (e.g. authz review), add **`owasp_api`** only if the text maps cleanly to an official API category; otherwise omit.
- [x] 3.3 Extend **`resolve_cheat_sheets`** (and call sites) with **`owasp_api.id`** optional argument and **three-tier** order: **`RULE_CHEAT_SHEETS[rule_id]`** → bundled **`owasp_api`** fallback map (when **`owasp_api`** present) → **`CATEGORY_FALLBACK[owasp.id]`**.
- [x] 3.4 Add **`RULE_CHEAT_SHEETS`** entries for API- or technology-relevant **`rule_id`** values where appropriate (e.g. **GraphQL** via `GraphQL_Cheat_Sheet.html` when a GraphQL-oriented rule exists or is added); add **curated** **`owasp_api.id`** → cheat sheet fallback entries only where justified.

## 4. Markdown report

- [x] 4.1 Implement **`#### OWASP API Security (2023)`** subsection per spec (conditional on **`owasp_api`** or API URLs in **`references`** after serialization), with deduped **`[title](url)`** bullets and ordering per spec.
- [x] 4.2 Ensure subsection plays well with existing **Cheat sheet** and **Further reading** behavior (no duplicate prose; URL dedup rules consistent with `markdown.py`).

## 5. Validation and tests

- [x] 5.1 Extend JSON/schema validation tests (if any) so **`owasp_api`** is optional and validated when present.
- [x] 5.2 Add **snapshot or unit tests** for at least one rule emitting **`owasp_api`** and for Markdown containing the new subsection when expected.
- [x] 5.3 Confirm **category filter** (`A01`–`A10`) unchanged; **`API*`** in filter list still rejected or ignored per current `caps` behavior—add test if missing.
- [x] 5.4 Add tests that **`resolve_cheat_sheets`** returns **GraphQL** (or another curated API technology sheet) for the intended **`rule_id`**, and that **owasp_api fallback** runs only when **`rule_id`** has no dedicated cheat sheet list.

## 6. Documentation

- [x] 6.1 Update **README** with short **API Security 2023 crosswalk** subsection: primary taxonomy **A01–A10**, optional **`owasp_api`**, static-only, link to OWASP API Security project.
