## Context

**v1.0.2** adds **`owasp_report_save`**. **`owasp_scan`** returns JSON only in the MCP result. Users still manually persist JSON when they want a file. **`owasp_scan_save`** closes that gap with **one call**, **explicit path**, and **no** extra round-trip through the client.

## Goals / Non-Goals

**Goals:**

- **Symmetry:** Same **absolute path**, **`overwrite`**, **atomic write**, and **parent mkdir** behavior as Markdown save (`design.md` in **`owasp-report-save-to-disk`**).
- **Payload:** Written file is **byte-identical** (as UTF-8 text) to serializing the **`run_scan`** return value with a stable, documented policy: **`json.dumps(..., indent=2, ensure_ascii=False)`** and a **single trailing newline**.
- **Tool result:** Compact confirmation dict; **not** the full envelope in the MCP tool return value.
- **Version:** **1.0.3** product metadata.

**Non-Goals:**

- **Per-category** MCP tools, **PyPI** publishing, **schema_version** bump (still **1.0**), **rulepack** change.

## Decisions

### D1 - One scan, one write

- **Choice:** **`owasp_scan_save`** calls **`run_scan` once** and writes that dict directly (no second scan, no streaming).
- **Rationale:** Matches mental model of **`owasp_scan`**; simplest parity tests.

### D2 - JSON encoding

- **Choice:** `json.dumps(envelope, indent=2, ensure_ascii=False) + "\n"` as the only file body.
- **Rationale:** Human-diffable; Unicode in `evidence` / descriptions preserved; trailing newline matches common CLI JSON tools.

### D3 - Confirmation dict

- **Choice:** Return **`path`**, **`bytes_written`**, **`truncated`**, **`finding_count`** (length of **`findings`**), **`rulepack_version`**, **`product_version`** mirroring **`owasp_scan`** metadata fields where applicable.
- **Rationale:** Agents confirm success without re-fetching file stats beyond size.

### D4 - File naming / PyPI

- **Choice:** Caller supplies full path (e.g. `.../owasp-scan-<timestamp>.json`); server does not invent names. **PyPI** not required.

## Risks / Trade-offs

| Risk | Mitigation |
|------|------------|
| Large repos produce large JSON files | Same caps as **`owasp_scan`**; document size in README briefly. |
| Duplicate logic with Markdown save | Reuse **`write_utf8_file_atomic`**; shared path validation helper optional in apply phase. |

## Migration Plan

Ship **1.0.3** as additive MCP surface; existing clients unaffected.

## Open Questions

- None for v1.0.3; **per-category façades** deferred.
