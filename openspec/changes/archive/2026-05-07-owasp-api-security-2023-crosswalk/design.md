## Context

**owasp-top10-mcp** emits static findings keyed to **OWASP Top 10:2025 (A01–A10)** with a stable JSON contract and Markdown reports. [OWASP API Security Top 10 (2023)](https://owasp.org/www-project-api-security/) is the conventional list for API-specific risk communication; its categories (**API1–API10**) do not align one-to-one with A01–A10. The product goal is to **surface** API Security officially (links + optional structured tags) while keeping **A01–A10** the single primary taxonomy for filtering and backward compatibility.

## Goals / Non-Goals

**Goals:**

- Add **optional** `owasp_api` **`{ year: 2023, id: "APIn" }`** on findings when a maintainer-approved **rule-level** crosswalk exists.
- Enrich **`references`** (and Markdown) with **bundled**, **offline-resolvable** URLs pointing at OWASP API Security documentation (hub and/or per-category pages as maintained by OWASP).
- Extend **OWASP Cheat Sheet Series** resolution so API- or protocol-relevant sheets (e.g. **GraphQL**) appear under the existing **`#### Cheat sheet`** subsection **when curated** for **`rule_id`**, with optional **second-tier** fallback keyed by **`owasp_api.id`** before A01–A10 category fallback.
- Keep **deterministic `finding.id`** stable when only optional API metadata or reference URLs are added (same canonical key as today).
- Preserve **v1 static-only** execution (no network fetches at scan time for this feature).

**Non-Goals:**

- **Filtering** scan results by API1–API10 in MCP tool parameters (defer to a future change if needed).
- Claiming **full** API Top 10 coverage or replacing A01–A10 as the primary field.
- **Dynamic** API testing (DAST), live OpenAPI validation against a server, or rate-limit verification.

## Decisions

1. **Primary field remains `owasp` (2025, A01–A10)**  
   **Rationale:** Existing clients, caps, sort order, and cheat-sheet fallback use `owasp.id`. **Alternative considered:** API-only findings — **rejected** as breaking and confusing.

2. **Optional `owasp_api` object shape:** `{ "year": 2023, "id": "API1" }` … **`API10`** — string labels **without** zero-padding, matching OWASP API Security Top 10:2023 documentation.  
   **Rationale:** Mirrors `owasp` object style and official naming. **Alternative:** single string field without year — **rejected**; year anchors edition when a future list ships.

3. **Crosswalk ownership:** Only **builtin rulepack** (and explicit engine-added reminders) set `owasp_api`; heuristics without a documented mapping **omit** the field.  
   **Rationale:** Avoid false precision. **Alternative:** auto-map A01→API1 — **rejected** (many-to-many reality).

4. **URL sourcing:** A **constants map** in code (like `OWASP_2025_SLUGS`) for **API1–API10** plus project hub URL; **no** HTTP fetch. Maintainers **verify** URLs against the live OWASP site during release (manual or scripted check outside the scan path).  
   **Rationale:** Matches cheat-sheet policy. **Alternative:** hardcode only hub URL — **acceptable fallback** where per-category URLs are unstable.

5. **Markdown presentation:** Add **`#### OWASP API Security (2023)`** when `owasp_api` is present **or** when the finding’s rendered `references` include at least one URL normalized to the API Security doc set (implementation-defined set of prefixes). Dedupe links; order: **category page** first if available, then **hub**.  
   **Rationale:** Visible in chat without reading JSON. **Alternative:** inline only — **rejected**; subsection is clearer.

6. **Finding ID key (D2b extension):** The canonical id key **MUST NOT** include `owasp_api` or API reference URLs — only existing fields (`rulepack_version`, `rule_id`, path, lines, snippet).  
   **Rationale:** Prevent id churn for consumers diffing scans.

7. **Product version:** Bump **1.0.5 → 1.0.6** with this behavior.

8. **Cheat sheet resolution order**  
   **`resolve_cheat_sheets`** (or equivalent) SHALL resolve in order: **(1)** `RULE_CHEAT_SHEETS[rule_id]`; **(2)** if absent, optional **`OWASP_API_CHEAT_FALLBACK[owasp_api.id]`** when the finding carries **`owasp_api`**; **(3)** if still absent, existing **`CATEGORY_FALLBACK[owasp.id]`**. All URLs remain under **`https://cheatsheetseries.owasp.org/cheatsheets/`** (or other maintainer-approved OWASP docs already allowed by the cheat sheet spec), **no runtime fetch**.  
   **Rationale:** Matches user expectation that GraphQL/API rules link to GraphQL (etc.) sheets without duplicate Markdown plumbing. **Alternative:** duplicate links only in API subsection — **rejected**; reuses **`#### Cheat sheet`**.

## Risks / Trade-offs

| Risk | Mitigation |
|------|------------|
| Stale or broken OWASP URLs after site moves | Release checklist: spot-check hub + category links; prefer hub URL in map if category URLs churn |
| Mappings imply guaranteed API coverage | Omit `owasp_api` when unsure; use `limitations` / `confidence` per existing patterns |
| Report noise | Subsection only when `owasp_api` or API URLs present; dedupe |

## Migration Plan

1. Implement schema + maps + rule crosswalks behind the new version.
2. Ship **1.0.6**; consumers ignore unknown JSON fields continue to work.
3. Rollback: revert release; saved JSON may contain `owasp_api` — downstream parsers should tolerate unknown keys (already best practice).

## Open Questions

- Exact **canonical URL** pattern for each API1–API10 page at ship time (to be resolved during implementation using the live OWASP site).
- Which **`owasp_api.id`** values warrant a non-empty cheat-sheet fallback list in v1 (curator decision; may start empty and grow with rule coverage).
