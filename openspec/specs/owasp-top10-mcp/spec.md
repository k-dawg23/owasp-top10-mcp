# owasp-top10-mcp Specification

## Purpose

**owasp-top10-mcp** is a **local** Model Context Protocol (MCP) server using **stdio**. It targets **solo developers and AI agents** who want a **fast, offline-capable, static** read of a repository against **OWASP Top 10:2025** themes (**A01–A10**), with **supplementary** linkage to **OWASP API Security Top 10:2023** (**API1–API10**) via optional **`owasp_api`** metadata and bundled documentation URLs where rules define a mapping. It does **not** require a hosted service or **PyPI** for end-user operation: a **git clone**, **venv**, and MCP config suffice. Findings are **advisory**; default scans do not run external security binaries or advisory APIs.

## Requirements

### Requirement: Specification purpose in canonical spec

The **Purpose** section of this file SHALL describe the intended audience (**solo developers and AI agents**), **stdio** MCP transport, **static** OWASP Top 10:2025 scope (**A01–A10**) as the **primary** taxonomy, **supplementary** OWASP API Security Top 10:2023 cross-mapping (**API1–API10**) where optional metadata applies, **local** operation without **requiring PyPI** for end users, and **advisory** findings (no mandatory hosted service for core operation).

#### Scenario: Purpose is substantive

- **WHEN** a reader opens this specification file after this change is applied
- **THEN** the **Purpose** section is concrete prose and does not consist solely of a **`TBD`** placeholder

### Requirement: Local MCP server exposes OWASP-oriented scan

The system SHALL provide a **local MCP server** that communicates over **stdio** (standard MCP transport) and exposes these tools, each driven by the same **static repository scan** aligned with **OWASP Top 10:2025** categories **A01** through **A10**:

- **`owasp_scan`:** canonical **JSON** findings envelope (no Markdown body).
- **`owasp_report`:** **Markdown** report for the **same parameters** as **`owasp_scan`** (human-readable, including navigable links where implemented).
- **`owasp_report_save`:** runs the same scan and writes that **Markdown** to a **client-supplied absolute path**, returning a **small JSON** confirmation (not the full report body).
- **`owasp_scan_save`:** runs the same scan and writes the **`owasp_scan`** JSON **envelope** to a **client-supplied absolute path**, returning a **small JSON** confirmation (not the full findings payload in the tool result).

#### Scenario: Agent invokes scan tool

- **WHEN** a connected MCP client invokes **`owasp_scan`** with a valid repository root
- **THEN** the server reads files from that repository according to configured glob rules and profiles without requiring a hosted service for core v1 operation

#### Scenario: User invokes Markdown report tool

- **WHEN** a client invokes **`owasp_report`** with the same arguments as a prior **`owasp_scan`**
- **THEN** the Markdown content enumerates the same findings as that scan's JSON (same `id` set, subject to documented sort order)

#### Scenario: Client may persist Markdown via save tool

- **WHEN** a client needs the Markdown report written to disk at a known absolute path
- **THEN** the client may invoke **`owasp_report_save`** with that path in addition to the scan parameters shared with **`owasp_report`**

#### Scenario: Client may persist JSON envelope via save tool

- **WHEN** a client needs the **`owasp_scan`** JSON envelope written to disk at a known absolute path
- **THEN** the client may invoke **`owasp_scan_save`** with that path in addition to the scan parameters shared with **`owasp_scan`**

### Requirement: v1 static-only execution

The system SHALL perform **v1 scanning using only in-process file reads and parsing**. It MUST NOT invoke external scanner binaries, subprocess-based security tools, or network advisory APIs as part of a default v1 scan.

#### Scenario: Default scan is offline and subprocess-free

- **WHEN** the scan tool is invoked with default options for v1
- **THEN** the implementation does not spawn subprocesses for external scanners and does not perform outbound network advisory lookups

### Requirement: Scan surface includes repo context beyond app source

The system SHALL include **v1 IaC-oriented paths** per **`design.md` D10** (Terraform `*.tf` / `*.tfvars`, optional convention dirs, `Chart.yaml`, Kustomize files, and **directory-scoped** Kubernetes YAML under `k8s/`, `kubernetes/`, `deploy/`, `manifests/`), in addition to container definitions, CI workflows, manifests, and lockfiles already specified.

#### Scenario: Docker and lockfiles are considered

- **WHEN** a repository contains a `Dockerfile` and a `package-lock.json` at discoverable paths
- **THEN** the scan includes these files in its eligible file set unless excluded by configuration or caps

#### Scenario: Terraform under infra/ is eligible

- **WHEN** a repository contains `infra/main.tf` matching the documented IaC glob set
- **THEN** that file is eligible for inclusion in the scan corpus like other matched paths

### Requirement: Language depth tiers

The system SHALL apply **tier-1** analysis depth to **Python** and **JavaScript/TypeScript** source files, **including Astro components** with extension **`.astro`** (treated as tier-1 **SFC-style** web files alongside extensions such as **`.vue`** and **`.svelte`**), using the **same tier-1 JavaScript/TypeScript-oriented rule path** as for those extensions **where implemented**. The system SHALL apply **best-effort** analysis to **other** languages using generic or lighter-weight checks. The scan metadata MUST indicate the active tiers (implementation-defined field).

#### Scenario: Python and TypeScript get deeper rules

- **WHEN** a scan encounters `.py` and `.ts` files under the repository root
- **THEN** tier-1 rules apply to those files and the scan metadata reports tier-1 coverage for Python and JavaScript/TypeScript

#### Scenario: Astro components get tier-1 web rules

- **WHEN** a scan encounters a **`.astro`** file under the repository root that is eligible per walker rules (not gitignored, within caps)
- **THEN** tier-1 rules apply to that file using the same JavaScript/TypeScript tier-1 analysis path used for **`.vue`** / **`.svelte`** tier-1 files **where implemented**, and findings MAY include rule hits driven by content in the **`.astro`** file (e.g. existing DOM or script-oriented heuristics)

### Requirement: Unified primary scan entrypoint

The system SHALL expose **`owasp_scan`** as the **primary JSON scan tool**, accepting optional **category filters** for one or more of **A01–A10** (year **2025** implied). It SHALL NOT return Markdown. Per-category MCP façade tools MAY be added later but are not required for v1 compliance.

#### Scenario: Filter to selected categories

- **WHEN** the client passes a list containing only `A05` and `A04`
- **THEN** findings returned are restricted to those OWASP categories plus always-included scan metadata

### Requirement: Markdown report tool

The system SHALL expose **`owasp_report`** as a distinct MCP tool accepting the **same parameters** as **`owasp_scan`**. It SHALL produce **Markdown** containing at least: **rulepack version**, **profile**, **truncation summary**, **counts by severity and OWASP category**, and **enumerated findings** with locations and links. **Navigable** Markdown (e.g. OWASP category links, CWE links, and supplementary reference links as implemented) is available only via this tool's return value (or via the file written by **`owasp_report_save`**), not via **`owasp_scan`**. PDF generation is **not** required in v1.

#### Scenario: Markdown via owasp_report only

- **WHEN** the client needs a human-readable report
- **THEN** the client invokes **`owasp_report`** (not **`owasp_scan`**) and receives Markdown content

#### Scenario: JSON response excludes Markdown

- **WHEN** the client invokes **`owasp_scan`**
- **THEN** the structured tool result contains **only** the JSON findings envelope and **does not** embed a full Markdown report

#### Scenario: Linked report in chat uses Markdown tool

- **WHEN** the client needs the full Markdown report body with navigable documentation links in the MCP chat UI
- **THEN** the client uses **`owasp_report`** (or **`owasp_report_save`** plus opening the file), not **`owasp_scan`** alone

### Requirement: Scan profiles and performance caps

The system SHALL support at least two profiles: **`agent_quick`** and **`human_full`**, mapping to documented defaults for **maximum files scanned**, **maximum bytes per file**, **maximum total bytes read**, **optional severity floor**, and **time budget**. When any limit stops the scan early, the response MUST set **`truncated`** to true and include **machine-readable truncation reasons**.

#### Scenario: Truncation is explicit

- **WHEN** the scan hits the configured `max_files` limit before visiting all eligible files
- **THEN** the scan result includes `truncated: true` and identifies `max_files` (or equivalent) among truncation reasons

### Requirement: Versioned JSON findings envelope

The system SHALL return findings as JSON with **`schema_version` `1.0`**, a **`scan`** metadata object, and a **`findings`** array. Scan metadata MUST include **`rulepack_version`** (starting at **`2025.1`**), **`profile`**, timing, truncation flags, and **limits applied**.

#### Scenario: Metadata carries rulepack version

- **WHEN** a scan completes successfully without internal error
- **THEN** the JSON includes `scan.rulepack_version` matching the bundled static rulepack release

### Requirement: Finding object contract

Each finding object SHALL include at minimum: **`id`**, **`rule_id`**, **`owasp`** (`year` **2025**, `id` **A01–A10**), **`title`**, **`description`**, **`severity`**, **`confidence`** (one of `rule` | `heuristic` | `review_required` or an equivalent documented enum), **`location`** (path and line range), **`evidence`** (short snippet), **`references`** (OWASP Top 10 category link encouraged; additional OWASP API Security documentation URLs allowed when static maps provide them), **`patch_candidate`** (boolean), **`fix_class`**, **`behavior_change`** (boolean), and **`blast_radius`**. Optional **`cwe`**, **`limitations`**, and **`owasp_api`** MAY be included.

When present, **`owasp_api`** SHALL be an object with **`year` `2023`** and **`id`** one of **`API1`** through **`API10`**. It MUST be omitted when the rulepack does not define a documented mapping for that finding.

The **`id`** SHALL be a **deterministic SHA-256** digest (**64-character lowercase hexadecimal**) computed from the **canonical key** defined in **`design.md` D2b**, which MUST NOT include **`owasp_api`** or supplemental reference URLs. The system MUST NOT use **UUIDs** for finding **`id`** in v1.

#### Scenario: Validator enforces patch_candidate invariants

- **WHEN** a finding has `patch_candidate` set to true
- **THEN** `fix_class` is `mechanical` and `behavior_change` is false

#### Scenario: Sensitive class forbids patch_candidate

- **WHEN** a finding has `fix_class` set to `sensitive` (authentication/session/authorization/crypto policy)
- **THEN** `patch_candidate` is false

#### Scenario: Stable id across identical reruns

- **WHEN** two **`owasp_scan`** invocations use identical `rulepack_version`, repository state, and parameters and the same physical finding is produced
- **THEN** the finding **`id`** values are identical

#### Scenario: Optional owasp_api omitted when unmapped

- **WHEN** a finding is emitted by a rule that has no maintainer-defined API Security crosswalk
- **THEN** the serialized finding does not include an **`owasp_api`** property

### Requirement: Narrow default for patch_candidate

The system SHALL default **`patch_candidate` to false** for all findings. Only findings produced by rules explicitly listed in a **`patch_candidate_allowlist`** bundled with the rulepack MAY set **`patch_candidate` to true** in v1.

#### Scenario: Unlisted rule never marks patch_candidate

- **WHEN** a finding is emitted by a generic heuristic rule not on the allowlist
- **THEN** `patch_candidate` is false

### Requirement: No silent remediation

The MCP server MUST NOT apply code changes to the **scanned repository**, write patches into that repository tree, or perform automated fixes there. Remediation MUST be expressed only as **textual guidance** and **structured fields** consumed by the user or external agent.

The server MAY expose **`owasp_report_save`** and **`owasp_scan_save`**, which write **only** the **report** (Markdown) or **JSON scan envelope**, respectively, to a filesystem path **explicitly provided by the client**. Those operations are **output persistence**, not remediation of project source.

#### Scenario: Scan-only tools do not modify the repo tree

- **WHEN** the client invokes only **`owasp_scan`** or **`owasp_report`**
- **THEN** the scanned repository working tree is unchanged by that invocation

#### Scenario: Explicit report save is not repo remediation

- **WHEN** the client invokes **`owasp_report_save`** with an absolute **`output_path`**
- **THEN** only the report file at **`output_path`** is created or replaced per that tool's contract; the scanned repository tree is not modified by the scanning logic

#### Scenario: Explicit JSON save is not repo remediation

- **WHEN** the client invokes **`owasp_scan_save`** with an absolute **`output_path`**
- **THEN** only the JSON file at **`output_path`** is created or replaced per that tool's contract; the scanned repository tree is not modified by the scanning logic

### Requirement: Client-agnostic MCP surface

The tool schema and descriptions SHALL NOT depend on a specific vendor client beyond standard MCP. The same server SHALL be usable from **Cursor**, **Codex**, and other MCP-capable hosts.

Each tool's description (e.g. docstring exposed as the tool's description) SHALL briefly state **when to use that tool** versus **`owasp_scan`**, **`owasp_report`**, **`owasp_report_save`**, and **`owasp_scan_save`** (primary use case and return type), using portable language only.

#### Scenario: Descriptor has no Cursor-only fields

- **WHEN** a maintainer inspects published tool definitions
- **THEN** tool descriptions use portable language and standard MCP schema shapes without client-proprietary extensions

#### Scenario: Tool choice is documented in descriptors

- **WHEN** a maintainer or agent reads the scan and report tool descriptions
- **THEN** each description distinguishes JSON scan vs Markdown string vs Markdown save confirmation vs JSON save confirmation in portable terms

### Requirement: Honest scope for supply chain without CVEs

When emitting findings mapped to **A03:2025**, the system MUST NOT claim **CVE identification** or **known-vulnerable version** correlation in v1. Such findings MUST be labeled with `limitations` including **`no_cve_correlation_in_v1`** or equivalent when the finding is purely structural/hygiene.

#### Scenario: Manifest hygiene is not a CVE claim

- **WHEN** the scan reports a git or tarball dependency source in a manifest
- **THEN** the finding does not include a CVE identifier unless a future version explicitly enables advisory correlation

### Requirement: Product version 1.0.6

The shipped package and scan metadata SHALL report **product version `1.0.6`** wherever **product version** is exposed (`pyproject.toml`, package `__version__`, and `scan.product_version` in JSON output).

#### Scenario: Scan metadata shows 1.0.6

- **WHEN** a scan completes successfully via any tool that includes scan metadata
- **THEN** the JSON envelope includes `scan.product_version` with value **`1.0.6`**

### Requirement: MCP tool writes Markdown report to an explicit path

The system SHALL expose **`owasp_report_save`**, an MCP tool that accepts the **same scan parameters** as **`owasp_report`** plus **`output_path`** (string) and optional **`overwrite`** (boolean, default **false**). The tool SHALL run the **same static scan** as **`owasp_scan`**, render Markdown with **`render_markdown`**, encode the body as **UTF-8**, and write it to **`output_path`**. The Markdown bytes SHALL be **identical** to those implied by invoking **`owasp_report`** with the same scan arguments under the same implementation (same normalization rules).

#### Scenario: Save succeeds with absolute path

- **WHEN** the client invokes **`owasp_report_save`** with a valid repository root, valid scan arguments, and **`output_path`** set to an absolute path in a writable directory where the file does not exist, and **`overwrite`** is false
- **THEN** the file is created and contains the UTF-8 Markdown report, and the tool returns a structured result including **`path`**, **`bytes_written`**, and **`truncated`** consistent with the scan envelope

#### Scenario: Relative path is rejected

- **WHEN** the client passes a relative **`output_path`** (e.g. `reports/out.md`)
- **THEN** the tool fails with an actionable error and does not create or truncate a file

#### Scenario: Existing file without overwrite is rejected

- **WHEN** the target file already exists and **`overwrite`** is false
- **THEN** the tool fails without modifying the existing file

#### Scenario: Overwrite replaces file atomically

- **WHEN** the target file already exists and **`overwrite`** is true
- **THEN** the file is replaced by the new report content without leaving a persistent partial file under normal failure modes (per **`design.md` D3**)

### Requirement: Save tool returns structured metadata

The **`owasp_report_save`** tool SHALL NOT return the full Markdown body as its primary payload. It SHALL return a **JSON-serializable** object that includes at minimum **`path`** (string, absolute path after normalization), **`bytes_written`** (non-negative integer), and **`truncated`** (boolean). It SHALL include **`rulepack_version`** and **`product_version`** in a form consistent with the **`owasp_scan`** envelope (either nested under a **`scan`** object or as top-level keys mirrored from that object).

#### Scenario: Agent receives confirmation payload

- **WHEN** **`owasp_report_save`** completes successfully
- **THEN** the tool result allows a client to display **`path`**, **`bytes_written`**, **`truncated`**, **`rulepack_version`**, and **`product_version`** without parsing the Markdown file.

### Requirement: MCP tool writes JSON scan envelope to an explicit path

The system SHALL expose **`owasp_scan_save`**, an MCP tool that accepts the **same scan parameters** as **`owasp_scan`** plus **`output_path`** (string) and optional **`overwrite`** (boolean, default **false**). The tool SHALL invoke the **same scan engine** as **`owasp_scan`** once, serialize the returned findings **envelope** (the same object shape as **`owasp_scan`**) to **UTF-8** using **`json.dumps`** with **`indent=2`**, **`ensure_ascii=False`**, and a **single trailing newline** after the JSON document, and write that text to **`output_path`**. The UTF-8 bytes SHALL decode to JSON equivalent to the **`owasp_scan`** result for the same arguments under the same implementation (same serialization policy).

#### Scenario: JSON save succeeds with absolute path

- **WHEN** the client invokes **`owasp_scan_save`** with valid scan arguments and **`output_path`** set to an absolute path in a writable directory where the file does not exist, and **`overwrite`** is false
- **THEN** the file is created and its contents parse as JSON equivalent to the **`owasp_scan`** envelope, and the tool returns a structured result including **`path`**, **`bytes_written`**, **`finding_count`**, **`truncated`**, **`rulepack_version`**, and **`product_version`**

#### Scenario: Relative JSON output path is rejected

- **WHEN** the client passes a relative **`output_path`** for **`owasp_scan_save`**
- **THEN** the tool fails with an actionable error and does not create or truncate a file

#### Scenario: Existing JSON file without overwrite is rejected

- **WHEN** the target file already exists and **`overwrite`** is false
- **THEN** the **`owasp_scan_save`** tool fails without modifying the existing file

#### Scenario: JSON overwrite replaces file atomically

- **WHEN** the target file already exists and **`overwrite`** is true
- **THEN** the file is replaced by the new JSON content using an atomic write strategy equivalent to **`owasp_report_save`** (temp file in the same directory, then replace)

### Requirement: JSON save tool returns structured metadata

The **`owasp_scan_save`** tool SHALL NOT return the full findings envelope as its primary payload. It SHALL return a **JSON-serializable** object with at least **`path`** (normalized absolute string), **`bytes_written`** (non-negative integer), **`finding_count`** (non-negative integer), **`truncated`** (boolean), **`rulepack_version`**, and **`product_version`**.

#### Scenario: Agent receives JSON save confirmation payload

- **WHEN** **`owasp_scan_save`** completes successfully
- **THEN** the tool result allows a client to display **`path`**, **`bytes_written`**, **`finding_count`**, **`truncated`**, **`rulepack_version`**, and **`product_version`** without parsing the saved file

### Requirement: Bundled OWASP cheat sheet map

The system SHALL ship a **static**, read-only **cheat sheet map** bundled with the package (under `owasp_top10_mcp/`). The map SHALL resolve **zero or more** cheat sheet entries (`title`, `url`) for a given finding using **`rule_id`** first; if none, an optional bundled fallback keyed by **`owasp_api.id`** when **`owasp_api`** is present; if still none, fall back by **`owasp.id`** (A01–A10). Resolution MUST NOT use network I/O at scan time. URLs SHOULD target **OWASP Cheat Sheet Series** or other maintainer-approved OWASP documentation pages.

#### Scenario: Offline resolution

- **WHEN** a scan runs with no network access
- **THEN** any cheat sheet links emitted in Markdown reports come only from the bundled map

### Requirement: Markdown cheat sheet subsection

For each finding, when resolution per **Bundled OWASP cheat sheet map** yields at least one distinct URL, the Markdown report SHALL include a **`#### Cheat sheet`** subsection for that finding with a Markdown bullet list of **`[title](url)`** links. URLs duplicated between rule-specific and fallback entries SHALL appear **once** (rule-level entries first, preserve first-seen order otherwise). When resolution yields no URLs, the subsection MUST be omitted entirely.

#### Scenario: Mapped rule renders cheat sheet link

- **WHEN** a finding's `rule_id` has at least one entry in the bundled map
- **THEN** the Markdown for that finding includes **`#### Cheat sheet`** and a link whose URL matches the map

#### Scenario: Unmapped rule omits subsection

- **WHEN** a finding's `rule_id` and `owasp.id` resolve to no cheat sheet entries
- **THEN** the Markdown for that finding does not include **`#### Cheat sheet`**

#### Scenario: Category fallback applies when rule unmapped

- **WHEN** a finding's `rule_id` has no entry but **`owasp.id`** has a configured fallback URL
- **THEN** the Markdown includes **`#### Cheat sheet`** with that fallback link

### Requirement: Cheat sheet resolution with API and technology supplements

Curators SHALL extend **`RULE_CHEAT_SHEETS`** with **OWASP Cheat Sheet Series** URLs where **technology- or API-specific** sheets apply (e.g. **GraphQL** when a **`rule_id`** targets GraphQL). Normative precedence for **`#### Cheat sheet`** remains: **`rule_id`**, then **`owasp_api.id`** fallback when present, then **A01–A10** category fallback, per **Bundled OWASP cheat sheet map**.

#### Scenario: Rule maps to GraphQL cheat sheet

- **WHEN** a finding’s **`rule_id`** is listed in **`RULE_CHEAT_SHEETS`** with the **GraphQL** cheat sheet URL
- **THEN** the Markdown **`#### Cheat sheet`** subsection includes that link (subject to existing deduplication rules)

#### Scenario: owasp_api fallback applies when rule unmapped

- **WHEN** a finding includes **`owasp_api`**, has **no** **`rule_id`** entry in **`RULE_CHEAT_SHEETS`**, and the bundled **`owasp_api.id`** fallback defines one or more cheat sheets for that **`id`**
- **THEN** **`#### Cheat sheet`** includes those fallback links

#### Scenario: Category fallback unchanged when no rule or API sheets

- **WHEN** a finding has **no** **`rule_id`** cheat sheets and **no** applicable **`owasp_api.id`** fallback
- **THEN** resolution uses **`owasp.id`** (**A01–A10**) category fallback only

### Requirement: Bundled OWASP API Security 2023 URL map

The system SHALL ship a **static** map from each **`API1`–`API10`** id to a canonical **2023** category documentation URL on `owasp.org`, plus a **hub** URL for the OWASP API Security project. URLs MUST be used only from bundled constants (no fetch at scan time).

#### Scenario: Offline API reference merge

- **WHEN** a finding includes **`owasp_api`**
- **THEN** **`references`** includes the category URL and hub per the bundled map unless already present (normalized dedupe)

### Requirement: Markdown OWASP API Security subsection

When a finding includes **`owasp_api`** or **`references`** contains an OWASP API Security documentation URL, the Markdown report SHALL include **`#### OWASP API Security (2023)`** with distinct navigable links (category before hub when **`owasp_api`** is set).

#### Scenario: Subsection present for API-mapped finding

- **WHEN** a finding has **`owasp_api`** with **`id`** **`API8`**
- **THEN** the Markdown for that finding includes **`#### OWASP API Security (2023)`** and a link under **`owasp.org/API-Security`**

### Requirement: Primary category filter unchanged

The **`categories`** parameter SHALL accept **only** **A01–A10** in v1 (not **`API*`** ids).

#### Scenario: API id in filter is invalid

- **WHEN** a client passes **`categories`** containing **`API1`**
- **THEN** the server rejects the request with **`ValueError`** (same class as other invalid category strings)
