## Context

**v1.0.1+** Markdown already surfaces **OWASP Top 10** category URLs, **CWE**, and **Further reading**. Official cheat sheets (e.g. **OWASP Cheat Sheet Series**) are high-signal next links for humans and agents. This change adds a **maintainer-curated** static map rather than heuristics or network lookup.

## Goals / Non-Goals

**Goals:**

- **Bundled map:** `rule_id` -> one or more `{title, url}`; optional **fallback** by **`owasp.id`** (A01-A10) when the rule is unmapped.
- **Markdown:** **`#### Cheat sheet`** with bullet links; **no** section if nothing resolved.
- **Trust:** URLs from a **maintainer-approved** list (primarily `cheatsheetseries.owasp.org` and closely related OWASP pages); document that **link rot** is possible.
- **Product:** **1.0.4**.

**Non-Goals:**

- Crawling or fetching URLs at scan time; **PyPI**; **per-category MCP façade** tools; tightening detection rules.

## Decisions

### D1 - Markdown-first scope; optional JSON

- **Default:** Ship **Markdown-only** cheat sheet links (**`#### Cheat sheet`**) for v1.0.4. **`owasp_report`** / **`owasp_report_save`** carry the same curated links as today's pattern for CWE and Further reading.
- **Opt-in JSON:** The implementer MAY add an **optional** **`cheat_sheets`** field on each **finding** object when **`owasp_scan`** / JSON save workflows must surface cheat sheet URLs **without** using Markdown. Use **only** when that parity is worth the extra envelope surface area.
- **JSON shape (if opted in):** **`cheat_sheets`**: list of **`{"title": str, "url": str}`**, equivalent to the deduplicated entries rendered in Markdown (same resolver). Field **MUST** be omitted or **SHOULD** be an empty list when nothing maps (pick one convention in **`tasks.md`** / tests and stick to it). **Not** a required field; **`schema_version`** stays **`1.0`**.
- **Rationale:** Keeps the default change small and preserves trust in **`findings`**. JSON is an explicit second step for solo users who rely on **JSON-only** automation.

### D2 - Storage

- **Choice:** Python module **or** JSON under `owasp_top10_mcp/` package data, loaded at import. Start with **subset** of rules (expand with tests as map grows).
- **Rationale:** Simple packaging with setuptools; no runtime network.

### D3 - Labels

- **Choice:** Titles like `OWASP Cheat Sheet - XSS` or sheet page title string; consistent `OWASP Cheat Sheet - ...` prefix where helpful.
- **Rationale:** Readable in raw Markdown.

### D4 - Dedupe

- **Choice:** Same URL repeated for rule + category fallback -> **one** link in the section (first-seen order: rule-specific first, then fallback).

### D5 - Version merge

- **Choice:** Delta uses **REMOVED** prior **Product version** requirement + **ADDED** **1.0.4**. Maintainer adjusts **REMOVED** header if main spec is already **1.0.3**.

## Risks / Trade-offs

| Risk | Mitigation |
|------|------------|
| Wrong sheet for a heuristic rule | Conservative mapping; start with high-confidence rules; category fallback weaker than rule-level. |
| Stale URL | Periodic review note in README; link to cheat sheet series index where appropriate. |

## Migration Plan

Patch release **1.0.4**; no config changes.

## Resolved (formerly Open Questions)

| Topic | Resolution |
|-------|------------|
| Optional **`cheat_sheets`** on findings in JSON | **`D1`**: **Default** is Markdown-only. **Opt in** during apply only if **`owasp_scan`** (or **`owasp_scan_save`**) must expose cheat sheet links without **`owasp_report`**. If opted in, use **`cheat_sheets`**: **`[{title, url}, ...]`**, optional, not required, same resolver as Markdown. |

## Open Questions

- None for v1.0.4 cheat sheet behavior.
