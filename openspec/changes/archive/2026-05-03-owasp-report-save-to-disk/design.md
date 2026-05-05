## Context

**v1.0.0** (and follow-on **v1.0.1** doc-links proposal) expose **`owasp_report`**, which returns Markdown as a **string** tool result. README already notes users can **save** that output manually. Exploration concluded that **automatic persistence** should be a **separate** capability: the MCP server must not pick hidden paths, and the **human or agent** should supply (and ideally confirm) the destination. This change implements that as **v1.0.2** without altering JSON shape or the existing Markdown tool.

## Goals / Non-Goals

**Goals:**

- **Explicit save:** New tool **`owasp_report_save`** writes the **same** Markdown body as **`owasp_report`** for identical arguments, to a **caller-provided absolute file path**.
- **Structured confirmation:** Return a compact **JSON-serializable** result (path, byte length, and key scan flags such as `truncated` / `rulepack_version` / `product_version`) so agents can quote outcomes in chat.
- **Safe defaults:** No overwrite unless **`overwrite=true`**; reject **relative** paths; prefer **atomic** commit of file contents.
- Ship **product version 1.0.2**; **rulepack `2025.1`** and **`schema_version` `1.0`** unchanged.

**Non-Goals (v1.0.2):**

- Generating filenames inside the server (no mandatory timestamp or `run_id` pattern; **documentation** may recommend patterns for clients).
- Saving **JSON** from **`owasp_scan`** to disk (callers can persist JSON themselves; revisit only if requested).
- PDF, cheat sheets, or new finding rules.

## Decisions

### D1 - New tool vs optional parameter on `owasp_report`

- **Choice:** Add **`owasp_report_save`** instead of overloading **`owasp_report`** with an optional path.
- **Rationale:** Keeps **`owasp_report`** return type stable (`str` only), makes "this call performs a side effect on disk" obvious in logs and client UIs, and avoids optional parameters that some clients treat as omissible by default.

### D2 - Path rules

- **Choice:** **`output_path`** MUST be **absolute** after minimal normalization (e.g. `pathlib.Path.resolve()` or documented equivalent). Relative paths are rejected with a clear MCP error.
- **Choice:** If the parent directory does not exist, **create** parent directories (mode as implemented per OS defaults; document umask expectations briefly in README).
- **Rationale:** Matches agent workflows that choose e.g. `~/reports/...` or workspace paths; avoids silent relative writes against an unclear CWD.

### D3 - Overwrite and atomic write

- **Choice:** If the target file exists and **`overwrite`** is false (default), fail without truncating. If **`overwrite`** is true, replace the file.
- **Choice:** Write to a **temporary file** in the **same directory** as the final file, then **`os.replace`** (or equivalent) into **`output_path`**.
- **Rationale:** Reduces risk of partial files on crash; behavior is familiar from tooling norms.

### D4 - Response shape

- **Choice:** Return **`dict`** with at least: **`path`** (string, normalized absolute path), **`bytes_written`** (int), **`truncated`** (bool from scan envelope), **`scan.rulepack_version`**, **`scan.product_version`** (or top-level mirror keys consistent with existing JSON envelope conventions).
- **Rationale:** Agents need confirmation without re-streaming the full Markdown in the tool result.

### D5 - Parity with `owasp_report`

- **Choice:** Implement by **`run_scan`** + **`render_markdown(envelope)`** then encode to **UTF-8** with **Unix newlines** (`\n`) to match **`owasp_report`** string encoding behavior (document if platform-specific newline normalization exists today).

## Risks / Trade-offs

| Risk | Mitigation |
|------|------------|
| Writes to sensitive locations | Caller responsibility + documentation: confirm path with user; server only validates absolute path and errors on obvious issues. |
| Symlink or mount surprises | Document that **`output_path`** is opened as the resolved path; optional test for symlink final target if feasible without OS-specific traps. |
| Large reports / disk full | Same as any file write; return actionable OS error message text in MCP error. |

## Migration Plan

- Release **v1.0.2** as a minor feature add. Existing integrations keep using **`owasp_report`** / **`owasp_scan`** only.

## Open Questions

- None blocking v1.0.2; optional future: **`owasp_scan_save`** for JSON mirroring this pattern.
