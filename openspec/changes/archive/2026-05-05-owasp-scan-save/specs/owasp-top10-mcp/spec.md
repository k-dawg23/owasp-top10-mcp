## REMOVED Requirements

### Requirement: Product version 1.0.2

**Reason:** Superseded by **product version 1.0.3** (this change adds **`owasp_scan_save`**).

**Migration:** After upgrade, expect **`scan.product_version`** **`1.0.3`**; no **`schema_version`** change.

## ADDED Requirements

### Requirement: Product version 1.0.3

The shipped package and scan metadata SHALL report **product version `1.0.3`** wherever **product version** is exposed (`pyproject.toml`, package `__version__`, and `scan.product_version` in JSON output).

#### Scenario: Scan metadata shows 1.0.3

- **WHEN** a scan completes successfully via any tool that includes scan metadata
- **THEN** the JSON envelope includes `scan.product_version` with value **`1.0.3`**

### Requirement: MCP tool writes JSON scan envelope to an explicit path

The system SHALL expose **`owasp_scan_save`**, an MCP tool that accepts the **same scan parameters** as **`owasp_scan`** plus **`output_path`** (string) and optional **`overwrite`** (boolean, default **false**). The tool SHALL invoke the **same scan engine** as **`owasp_scan`** once, serialize the returned findings **envelope** (the same object shape as **`owasp_scan`**) to **UTF-8** using **`json.dumps`** with **`indent=2`**, **`ensure_ascii=False`**, and a **single trailing newline** after the JSON document, and write that text to **`output_path`**. The UTF-8 bytes SHALL decode to JSON equivalent to the **`owasp_scan`** result for the same arguments under the same implementation (same serialization policy).

#### Scenario: Save succeeds with absolute path

- **WHEN** the client invokes **`owasp_scan_save`** with valid scan arguments and **`output_path`** set to an absolute path in a writable directory where the file does not exist, and **`overwrite`** is false
- **THEN** the file is created and its contents parse as JSON equivalent to the **`owasp_scan`** envelope, and the tool returns a structured result including **`path`**, **`bytes_written`**, **`finding_count`**, **`truncated`**, **`rulepack_version`**, and **`product_version`**

#### Scenario: Relative path is rejected

- **WHEN** the client passes a relative **`output_path`**
- **THEN** the tool fails with an actionable error and does not create or truncate a file

#### Scenario: Existing file without overwrite is rejected

- **WHEN** the target file already exists and **`overwrite`** is false
- **THEN** the tool fails without modifying the existing file

#### Scenario: Overwrite replaces file atomically

- **WHEN** the target file already exists and **`overwrite`** is true
- **THEN** the file is replaced by the new JSON content using an atomic write strategy equivalent to **`owasp_report_save`** (temp file in the same directory, then replace)

### Requirement: JSON save tool returns structured metadata

The **`owasp_scan_save`** tool SHALL NOT return the full findings envelope as its primary payload. It SHALL return a **JSON-serializable** object with at least **`path`** (normalized absolute string), **`bytes_written`** (non-negative integer), **`finding_count`** (non-negative integer), **`truncated`** (boolean), **`rulepack_version`**, and **`product_version`**.

#### Scenario: Agent receives confirmation payload

- **WHEN** **`owasp_scan_save`** completes successfully
- **THEN** the tool result allows a client to display **`path`**, **`bytes_written`**, **`finding_count`**, **`truncated`**, **`rulepack_version`**, and **`product_version`** without parsing the saved file
