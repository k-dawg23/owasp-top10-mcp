## ADDED Requirements

### Requirement: Specification purpose in canonical spec

The file **`openspec/specs/owasp-top10-mcp/spec.md`** SHALL include a **Purpose** section before **Requirements** whose prose matches **`design.md` D1** in substance: **solo developers and AI agents**, **stdio MCP**, **static** OWASP Top 10:2025 (**A01–A10**), **local** operation **without requiring PyPI** for end users, and **advisory** findings (no mandatory hosted service).

#### Scenario: Purpose is substantive

- **WHEN** a reader opens the canonical specification file after this change is applied
- **THEN** the **Purpose** section is concrete prose and does not consist solely of a **`TBD`** placeholder

## MODIFIED Requirements

### Requirement: Local MCP server exposes OWASP-oriented scan

The system SHALL provide a **local MCP server** that communicates over **stdio** (standard MCP transport) and exposes these tools, each driven by the same **static repository scan** aligned with **OWASP Top 10:2025** categories **A01** through **A10**:

- **`owasp_scan`:** canonical **JSON** findings envelope (no Markdown body).
- **`owasp_report`:** **Markdown** report for the **same parameters** as **`owasp_scan`** (human-readable, including navigable links where implemented).
- **`owasp_report_save`:** runs the same scan and writes that **Markdown** to a **client-supplied absolute path**, returning a **small JSON** confirmation (not the full report body).

#### Scenario: Agent invokes scan tool

- **WHEN** a connected MCP client invokes **`owasp_scan`** with a valid repository root
- **THEN** the server reads files from that repository according to configured glob rules and profiles without requiring a hosted service for core v1 operation

#### Scenario: User invokes Markdown report tool

- **WHEN** a client invokes **`owasp_report`** with the same arguments as a prior **`owasp_scan`**
- **THEN** the Markdown content enumerates the same findings as that scan's JSON (same `id` set, subject to documented sort order)

#### Scenario: Client may persist Markdown via save tool

- **WHEN** a client needs the Markdown report written to disk at a known absolute path
- **THEN** the client may invoke **`owasp_report_save`** with that path in addition to the scan parameters shared with **`owasp_report`**

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

### Requirement: No silent remediation

The MCP server MUST NOT apply code changes to the **scanned repository**, write patches into that repository tree, or perform automated fixes there. Remediation MUST be expressed only as **textual guidance** and **structured fields** consumed by the user or external agent.

The server MAY expose **`owasp_report_save`**, which writes **only** the Markdown **report** to a filesystem path **explicitly provided by the client**. That operation is **report persistence**, not remediation of project source.

#### Scenario: Scan-only tools do not modify the repo tree

- **WHEN** the client invokes only **`owasp_scan`** or **`owasp_report`**
- **THEN** the scanned repository working tree is unchanged by that invocation

#### Scenario: Explicit report save is not repo remediation

- **WHEN** the client invokes **`owasp_report_save`** with an absolute **`output_path`**
- **THEN** only the report file at **`output_path`** is created or replaced per that tool's contract; the scanned repository tree is not modified by the scanning logic

### Requirement: Client-agnostic MCP surface

The tool schema and descriptions SHALL NOT depend on a specific vendor client beyond standard MCP. The same server SHALL be usable from **Cursor**, **Codex**, and other MCP-capable hosts.

Each tool's description (e.g. docstring exposed as the tool's description) SHALL briefly state **when to use that tool** versus **`owasp_scan`**, **`owasp_report`**, and **`owasp_report_save`** (primary use case and return type), using portable language only.

#### Scenario: Descriptor has no Cursor-only fields

- **WHEN** a maintainer inspects published tool definitions
- **THEN** tool descriptions use portable language and standard MCP schema shapes without client-proprietary extensions

#### Scenario: Tool choice is documented in descriptors

- **WHEN** a maintainer or agent reads the three scan/report tool descriptions
- **THEN** each description distinguishes JSON scan vs Markdown string vs save-to-disk confirmation in portable terms
