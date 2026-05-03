## Context

**v1.0.0** ships `owasp_report` Markdown with **OWASP Top 10:2025** category links in the summary and per-finding **Category link** line. Findings JSON may already include **`cwe`** (integers) and **`references`** (URLs); the Markdown renderer does not yet surface **all** references as an explicit link list, nor **CWE** as MITRE links. Exploration noted future work (cheat sheets per rule, save-to-disk); **v1.0.1** scopes to **documentation depth** in Markdown only.

## Goals / Non-Goals

**Goals:**

- Release **product v1.0.1** with improved **human** report navigability.
- **CWE:** For each finding with `cwe` populated, render **clickable** links using `https://cwe.mitre.org/data/definitions/<id>.html` (stable MITRE pattern).
- **References:** Render **Further reading** only for **supplementary** URLs (see **D3**): one Markdown link per remaining URL after excluding the primary category URL, with sensible labels (e.g. host + path snippet or "OWASP Top 10:2025 - Ax" when applicable).
- **Preserve** existing category links and report structure where possible.
- Keep **`schema_version` `1.0`** and **rulepack `2025.1`**.

**Non-Goals (v1.0.1):**

- Curated **OWASP Cheat Sheet** map by `rule_id`.
- **Saving** Markdown to disk via MCP (separate change; client still "asks" for path).
- Changing **finding** detection rules or JSON shape (beyond version constants).

## Decisions

### D1 - CWE URL format

- **Choice:** `https://cwe.mitre.org/data/definitions/{id}.html` for integer CWE ids.
- **Rationale:** Matches CWE's public definitions pages; works in Cursor, GitHub, and browsers.

### D2 - References section labels

- **Choice:** For each URL, if it matches a known OWASP Top 10 2025 category URL prefix, label `OWASP Top 10:2025 - {Ax}`; else use hostname + short path or raw `Documentation` + index.
- **Rationale:** Readable in Markdown source and when clicked.

### D3 - Dedupe: Category link vs Further reading

**Single rule (tests are source of truth for behavior):**

1. **Category link** - Always render the dedicated line **once** per finding: primary OWASP Top 10:2025 page for `finding["owasp"]["id"]`, using the same canonical URL as today (`owasp_top10_url`).

2. **Further reading** - Include **only** URLs from `finding["references"]` that are **not** the same document as that primary category page, using **URL normalization** (below). Order: preserve first-seen order from `references` after deduplication.

3. **Omit empty sections** - If no URLs remain after exclusion, **do not** render a **Further reading** heading or placeholder.

4. **CWE block** - Unrelated to reference dedupe; always render when `cwe` is non-empty.

**Normalization (implement once, reuse in tests):**  
`normalize_doc_url(url: str) -> str` SHALL be used for comparisons only:

- Strip leading/trailing ASCII whitespace.
- Lowercase the **scheme** and **host** (e.g. `HTTPS` -> `https`).
- Remove a **single** trailing `/` from the path (so `.../A07_.../` and `.../A07_...` match).
- Do **not** strip meaningful path segments; do not follow redirects.

**Test matrix (behavioral contract):**

| `references` (examples) | Category A07 URL | Further reading |
|---------------------|------------------|----------------|
| Only A07 category URL | same | **omitted** |
| A07 + `https://example.com/doc` | A07 | **one** link -> example.com |
| Only `https://example.com/doc` | A07 | **one** link -> example.com |

### D4 - Versioning

- **Product:** **1.0.1** in `pyproject.toml`, `owasp_top10_mcp/__init__.py`, `scan` metadata `product_version`.
- **Rulepack:** **2025.1** unchanged.

## Risks / Trade-offs

| Risk | Mitigation |
|------|------------|
| Noisy **Further reading** if `references` grows | Rare today; future cap optional (not v1.0.1). |
| CWE id invalid / missing on MITRE | Still link; MITRE shows 404 for invalid ids - rules should emit valid CWEs only. |

## Migration Plan

- Ship as **patch** release **v1.0.1**; consumers see richer Markdown without config changes.

## Resolved (formerly Open Questions)

| Topic | Resolution |
|--------|------------|
| Dedupe **Category link** vs **Further reading** | **`design.md` D3** - **Further reading** excludes URLs equal to the primary category URL after **`normalize_doc_url`**; **Category link** always shown; empty **Further reading** omitted. |

## Open Questions

- None for v1.0.1 dedupe policy.
