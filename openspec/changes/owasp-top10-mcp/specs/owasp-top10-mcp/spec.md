## ADDED Requirements

### Requirement: Local MCP server exposes OWASP-oriented scan

The system SHALL provide a **local MCP server** that communicates over **stdio** (standard MCP transport) and exposes **`owasp_scan`** (canonical JSON results) and **`owasp_report`** (Markdown narrative for the same parameters), each running a **static repository scan** aligned with **OWASP Top 10:2025** categories **A01** through **A10**.

#### Scenario: Agent invokes scan tool

- **WHEN** a connected MCP client invokes **`owasp_scan`** with a valid repository root
- **THEN** the server reads files from that repository according to configured glob rules and profiles without requiring a hosted service for core v1 operation

#### Scenario: User invokes Markdown report tool

- **WHEN** a client invokes **`owasp_report`** with the same arguments as a prior **`owasp_scan`**
- **THEN** the Markdown content enumerates the same findings as that scan’s JSON (same `id` set, subject to documented sort order)

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

The system SHALL apply **tier-1** analysis depth to **Python** and **JavaScript/TypeScript** source files, and **best-effort** analysis to **other** languages using generic or lighter-weight checks. The scan metadata MUST indicate the active tiers (implementation-defined field).

#### Scenario: Python and TypeScript get deeper rules

- **WHEN** a scan encounters `.py` and `.ts` files under the repository root
- **THEN** tier-1 rules apply to those files and the scan metadata reports tier-1 coverage for Python and JavaScript/TypeScript

### Requirement: Unified primary scan entrypoint

The system SHALL expose **`owasp_scan`** as the **primary JSON scan tool**, accepting optional **category filters** for one or more of **A01–A10** (year **2025** implied). It SHALL NOT return Markdown. Per-category MCP façade tools MAY be added later but are not required for v1 compliance.

#### Scenario: Filter to selected categories

- **WHEN** the client passes a list containing only `A05` and `A04`
- **THEN** findings returned are restricted to those OWASP categories plus always-included scan metadata

### Requirement: Markdown report tool

The system SHALL expose **`owasp_report`** as a distinct MCP tool accepting the **same parameters** as **`owasp_scan`**. It SHALL produce **Markdown** containing at least: **rulepack version**, **profile**, **truncation summary**, **counts by severity and OWASP category**, and **enumerated findings** with locations and links. PDF generation is **not** required in v1.

#### Scenario: Markdown via owasp_report only

- **WHEN** the client needs a human-readable report
- **THEN** the client invokes **`owasp_report`** (not **`owasp_scan`**) and receives Markdown content

#### Scenario: JSON response excludes Markdown

- **WHEN** the client invokes **`owasp_scan`**
- **THEN** the structured tool result contains **only** the JSON findings envelope and **does not** embed a full Markdown report

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

Each finding object SHALL include at minimum: **`id`**, **`rule_id`**, **`owasp`** (`year` **2025**, `id` **A01–A10**), **`title`**, **`description`**, **`severity`**, **`confidence`** (one of `rule` | `heuristic` | `review_required` or an equivalent documented enum), **`location`** (path and line range), **`evidence`** (short snippet), **`references`** (OWASP category link encouraged), **`patch_candidate`** (boolean), **`fix_class`**, **`behavior_change`** (boolean), and **`blast_radius`**. Optional **`cwe`** and **`limitations`** MAY be included.

The **`id`** SHALL be a **deterministic SHA-256** digest (**64-character lowercase hexadecimal**) computed from the **canonical key** defined in **`design.md` D2b**. The system MUST NOT use **UUIDs** for finding **`id`** in v1.

#### Scenario: Validator enforces patch_candidate invariants

- **WHEN** a finding has `patch_candidate` set to true
- **THEN** `fix_class` is `mechanical` and `behavior_change` is false

#### Scenario: Sensitive class forbids patch_candidate

- **WHEN** a finding has `fix_class` set to `sensitive` (authentication/session/authorization/crypto policy)
- **THEN** `patch_candidate` is false

#### Scenario: Stable id across identical reruns

- **WHEN** two **`owasp_scan`** invocations use identical `rulepack_version`, repository state, and parameters and the same physical finding is produced
- **THEN** the finding **`id`** values are identical

### Requirement: Narrow default for patch_candidate

The system SHALL default **`patch_candidate` to false** for all findings. Only findings produced by rules explicitly listed in a **`patch_candidate_allowlist`** bundled with the rulepack MAY set **`patch_candidate` to true** in v1.

#### Scenario: Unlisted rule never marks patch_candidate

- **WHEN** a finding is emitted by a generic heuristic rule not on the allowlist
- **THEN** `patch_candidate` is false

### Requirement: No silent remediation

The MCP server MUST NOT apply code changes, write patches to disk, or perform automated fixes. Remediation MUST be expressed only as **textual guidance** and **structured fields** consumed by the user or external agent.

#### Scenario: Tool output is advisory only

- **WHEN** the scan completes with one or more findings
- **THEN** the repository working tree is unchanged by the scan tool invocation alone

### Requirement: Client-agnostic MCP surface

The tool schema and descriptions SHALL NOT depend on a specific vendor client beyond standard MCP. The same server SHALL be usable from **Cursor**, **Codex**, and other MCP-capable hosts.

#### Scenario: Descriptor has no Cursor-only fields

- **WHEN** a maintainer inspects published tool definitions
- **THEN** tool descriptions use portable language and standard MCP schema shapes without client-proprietary extensions

### Requirement: Honest scope for supply chain without CVEs

When emitting findings mapped to **A03:2025**, the system MUST NOT claim **CVE identification** or **known-vulnerable version** correlation in v1. Such findings MUST be labeled with `limitations` including **`no_cve_correlation_in_v1`** or equivalent when the finding is purely structural/hygiene.

#### Scenario: Manifest hygiene is not a CVE claim

- **WHEN** the scan reports a git or tarball dependency source in a manifest
- **THEN** the finding does not include a CVE identifier unless a future version explicitly enables advisory correlation
