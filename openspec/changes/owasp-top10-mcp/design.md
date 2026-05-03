## Context

The proposer is a **solo user** driving **AI agents** (Cursor, Codex, and local inference stacks such as **llama.cpp**, **Ollama**, **LM Studio**). The repository under analysis may use **many languages and stacks**. Prior exploration fixed **v1 scope**: static reads only, **deeper rules for Python and JavaScript/TypeScript**, **broader repo surface** (Docker, CI, lockfiles, IaC), **two MCP tools** (`owasp_scan` + `owasp_report`), **JSON for agents** and **Markdown for humans**, strict **non-goals** (no DAST, no full SDLC), and conservative **`patch_candidate`** policy.

## Goals / Non-Goals

**Goals:**

- Ship **owasp-top10-mcp v1.0.0** as a **local MCP server (stdio)** with **`owasp_scan`** returning **versioned JSON findings** and **`owasp_report`** returning a **Markdown report** for the same scan parameters.
- Map findings to **OWASP Top 10:2025** categories **A01–A10** with honest confidence (`rule` / `heuristic` / `review_required`—pick one enum in implementation).
- Include **rulepack versioning** (initial **`2025.1`**) in scan metadata and Markdown header.
- Enforce **performance caps** and emit **truncation** metadata rather than hanging or implying full coverage when limited.
- Support **suggest-and-fix** *policy fields* only: **no silent or server-side apply** of patches.

**Non-Goals:**

- **Runtime/DAST**, exploitation proofs, or “pentest-grade” validation.
- **Network advisory/OSV/CVE** correlation and **subprocess** third-party scanners in **v1** (explicitly deferred).
- **PDF** report generation in v1 (Markdown only; PDF may be post-processed externally later).
- **Ten separate MCP tools** for A01–A10 in v1 (optional future thin wrappers only).
- **Guaranteed** detection completeness or exploitability.

## Decisions

### D1 — Implementation stack (default)

- **Default:** implement the MCP server in **Python** (strong ecosystem for file I/O, packaging via **`uv`** or venv).
- **Python:** minimum **`3.11+`** (`tomllib`, typing, performance).
- **MCP SDK:** official **[Model Context Protocol Python SDK](https://github.com/modelcontextprotocol/python-sdk)**; PyPI package **`mcp`**; pin a release in `pyproject.toml` (track SDK **v1.x** branch per upstream docs).
- **Alternatives considered:** Node/TypeScript; rejected as default for solo static-scan ergonomics.
- **Resolution:** If implementation starts in another language/SDK, update this decision and `tasks.md` consistently.

### D2 — `owasp_scan` and `owasp_report` (two tools)

- **`owasp_scan`:** parameters: `repo_root`, optional `categories[]` (A01–A10), `profile` (`agent_quick` | `human_full`), optional cap overrides. Returns **only** the **canonical versioned JSON** findings envelope. **No Markdown** in this response.
- **`owasp_report`:** **same parameters** as `owasp_scan`. Invokes the **same scan engine** and returns **Markdown** (human-readable report body). **Parity:** for identical arguments, the report MUST reflect the **same findings** as the JSON (`id`, count, and documented sort order—e.g. severity then path then line).
- **Rationale:** stable JSON for agents/local LLM tool parsers; Markdown fetched only when the user wants a readable artifact.
- **Alternatives:** `include_markdown` flag on a single tool—rejected to avoid variable response shapes.
- **Ten OWASP façade tools** remain deferred.

### D2b — Finding `id` (deterministic hash, not UUID)

- **`id`** MUST be **SHA-256** encoded as **64-character lowercase hexadecimal**.
- **Canonical input string** (UTF-8): concatenate the following fields with ASCII separator **`|`** (pipe): `rulepack_version`, `rule_id`, path (repo-relative, **forward slashes only**), `start_line`, `end_line`, **normalized snippet** (from `evidence.snippet`: strip leading/trailing whitespace; replace internal runs of whitespace with a single space).
- **Stability:** bumping `rulepack_version` while keeping the same physical finding MAY change `id`—that is intentional when rules change.
- **UUIDs:** do **not** use UUIDs for finding **`id`** in v1. Optional **`run_id`** (UUID) in **`scan`** metadata is allowed for logging only.

### D3 — Static-only v1 and honest A03 scope

- **Choice:** v1 performs **file reads + in-repo parsing** only. **A03** in v1 means **dependency/install surface hygiene** (manifests, lockfile presence/patterns, risky dependency sources) **without** CVE mapping.
- **Future:** optional online OSV with cache, or subprocess `npm audit` / `pip-audit`, or bundled advisory snapshot—**explicit opt-in** and version bump.

### D4 — Network posture

- **Choice:** **fully offline** for v1 core scan—no outbound calls.
- **Future:** when advisories are added, support **online-with-cache** for solo dev and **offline/snapshot** mode for strict CI.

### D5 — Performance defaults (initial; tune after dogfood)

| Knob | `agent_quick` (default for agents) | `human_full` |
|------|-----------------------------------|--------------|
| `max_files` | 500–2000 (start ~**1000**) | higher (e.g. **5000**) |
| `max_bytes_per_file` | **512 KB–1 MB** | same or higher |
| `max_total_bytes` | **~100 MB** | **~500 MB** |
| `severity_floor` | **`medium`** default | **`low`** or `info` allowed |
| `time_budget_ms` | **60_000–120_000** | **300_000+** |
| Excludes | `.git`, `node_modules`, common `dist/build/coverage` | same + configurable |

Always return **`truncated`** + **`truncation_reasons[]`** when limits hit.

### D6 — Finding JSON schema (v1)

- Envelope: **`schema_version`: `"1.0"`**, **`scan`** metadata, **`findings`** array.
- Finding fields (normative list in spec): `id`, `rule_id`, `owasp` (`year`, `id`), optional `cwe`, `title`, `description`, `severity`, `confidence`, `location`, `evidence`, `references`, **`patch_candidate`** (default **false**), **`fix_class`**, **`behavior_change`**, **`blast_radius`**, optional **`limitations[]`**.
- **Invariants:** If `patch_candidate` is `true`, require `fix_class === mechanical` and `behavior_change === false`; `fix_class === sensitive` (authz/crypto/session) ⇒ `patch_candidate === false`.

### D7 — `patch_candidate` allowlist (v1)

- Start with **empty or micro allowlist** (e.g. narrowly defined **HTML `target="_blank"` without `rel="noopener"`**). Expand only after measuring false positives.
- **Meaning:** “low-risk *proposal* candidate for human/agent to draft,” **not** “safe to apply.”

### D8 — Distribution for solo use

- **Primary:** **clone + run** via **`uv run`** or **venv + `python -m …`**; document **Cursor `mcp.json`** snippet.
- **Deferred:** PyPI/npm publish, Docker image—add when pain justifies.

### D9 — Multi-host agent compatibility

- Tool descriptions and JSON MUST be **host-agnostic** so the same server works with **Cursor**, **Codex**, and **local chat UIs** that speak MCP. No vendor-specific assumptions in the protocol surface.

### D10 — Minimal IaC file globs (v1)

Start **narrow** to avoid scanning every random YAML in a repo; **extend in later patches** as new rules need them. Eligible paths are **unioned** with Docker/CI/manifest logic elsewhere. All are relative to `repo_root` and subject to **caps** and **default excludes**.

| Intent | Glob pattern | Notes |
|--------|----------------|------|
| Terraform | `**/*.tf`, `**/*.tfvars` | Root module and vars; no automatic `.terraform/` traversal |
| Terraform dirs (optional convention) | `infra/**/*.tf`, `iac/**/*.tf`, `terraform/**/*.tf` | Catches common layouts without scanning entire tree twice—implementation may dedupe |
| Helm | `**/Chart.yaml` | Use parent directory as chart root for related `values.yaml` / `templates/*.yaml` only when rules need them |
| Kustomize | `**/kustomization.yaml`, `**/kustomization.yml` | |
| Kubernetes-style manifests | `k8s/**/*.yaml`, `k8s/**/*.yml`, `kubernetes/**/*.yaml`, `kubernetes/**/*.yml`, `deploy/**/*.yaml`, `deploy/**/*.yml`, `manifests/**/*.yaml`, `manifests/**/*.yml` | **Directory-convention** YAML only; avoids `**/*.yaml` repo-wide |

**Deferred (not v1 unless added explicitly later):** Ansible playbooks, Pulumi YAML, CloudFormation `*.template`, ARM JSON, Helm `templates/**/*.tpl` content (may add when rules exist).

## Risks / Trade-offs

| Risk | Mitigation |
|------|------------|
| **False confidence** on static heuristics | Default **`patch_candidate: false`**; use `review_required` / `heuristic` liberally; document limitations per finding and scan. |
| **Uneven language depth** | Label **tier-1** vs **best-effort** in metadata or rule prefixes; tune Py/JS packs first. |
| **Large-repo timeouts** | Hard **time_budget** + **truncation** reporting. |
| **A06 / design** largely not automatable | Emit **structured “review prompts”** as low-severity or `review_required` items—clearly labeled, not as “bugs found.” |
| **Solo maintainer load** | Keep v1 static-only; defer scanners/CVEs to v2. |

## Migration Plan

- **New component:** no production migration. **Rollout:** document install, bump **rulepack** (`2025.1` → `2025.2`) when rules change materially.
- **Rollback:** stop enabling the MCP server in client config; no data migrations.

## Resolved (formerly Open Questions)

| Topic | Resolution |
|--------|------------|
| MCP SDK / Python | Official [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk); **Python 3.11+**. |
| Markdown delivery | **`owasp_report`** is a **separate MCP tool**; **`owasp_scan`** returns **JSON only**. |
| IaC globs | **Minimal set** per **D10**; extend when new rules land. |
| Finding `id` | **SHA-256** of **canonical finding key** per **D2b**; **not** UUIDs. |

## Open Questions

- None blocking v1 proposal/design; optional **`run_id`** (UUID) in scan metadata left to implementation convenience.
