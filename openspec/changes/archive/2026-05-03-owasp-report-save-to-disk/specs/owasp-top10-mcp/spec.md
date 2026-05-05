## ADDED Requirements

### Requirement: Product version 1.0.2

The shipped package and scan metadata SHALL report **product version `1.0.2`** wherever **product version** is exposed (`pyproject.toml`, package `__version__`, and `scan.product_version` in JSON output).

#### Scenario: Scan metadata shows 1.0.2

- **WHEN** a scan completes successfully via any tool that includes scan metadata
- **THEN** the JSON envelope includes `scan.product_version` with value **`1.0.2`**

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
