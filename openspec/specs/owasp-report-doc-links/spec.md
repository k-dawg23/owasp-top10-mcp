# owasp-report-doc-links Specification

## Purpose
TBD - created by archiving change owasp-report-doc-links. Update Purpose after archive.
## Requirements
### Requirement: Product version 1.0.1

The shipped package and scan metadata SHALL report **product version `1.0.1`** where **product version** is exposed (`pyproject.toml`, package `__version__`, and `scan.product_version` in JSON output).

#### Scenario: Scan metadata shows new product version

- **WHEN** a scan completes successfully
- **THEN** the JSON envelope includes `scan.product_version` with value **`1.0.1`**

### Requirement: Markdown CWE links

The Markdown report SHALL include, for each finding that has a non-empty **`cwe`** array in JSON, a **clickable** Markdown link per CWE id pointing to **`https://cwe.mitre.org/data/definitions/<id>.html`** (integer **id** from the finding).

#### Scenario: Finding with CWE renders MITRE links

- **WHEN** a finding includes `"cwe": [89]` in JSON and appears in the Markdown report
- **THEN** the Markdown contains a link whose URL is `https://cwe.mitre.org/data/definitions/89.html`

#### Scenario: Finding without CWE omits CWE subsection

- **WHEN** a finding has no `cwe` field or an empty list
- **THEN** the Markdown does not claim CWE identifiers for that finding

### Requirement: Markdown Further reading from references

The Markdown report MAY include a **Further reading** subsection for a finding **only when** there is at least one URL in **`references`** that is **not** equivalent to that finding's **primary OWASP Top 10:2025 category URL** under **`normalize_doc_url`** as defined in **`design.md` D3**. For each remaining URL, the report SHALL render **`[label](url)`** with labels per **`design.md` D2**. URLs SHALL be **deduplicated** by **`normalize_doc_url`** while preserving first-seen order.

#### Scenario: Category-only references omit Further reading

- **WHEN** a finding's `references` contains only URLs that normalize to the same value as **`owasp_top10_url`** for that finding's `owasp.id`
- **THEN** the Markdown for that finding does not include a **Further reading** heading

#### Scenario: Supplemental reference appears in Further reading

- **WHEN** a finding's `references` includes `https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/` and `https://example.com/security-guide`
- **THEN** the Markdown includes **Category link** to the A07 page **and** **Further reading** includes only `[...](https://example.com/security-guide)` (or equivalent label per D2)

#### Scenario: References without category URL fully listed

- **WHEN** a finding's `references` contains only `https://example.com/security-guide` and the finding maps to **A07**
- **THEN** **Further reading** includes that example.com link and **Category link** still links to A07

### Requirement: Preserve existing OWASP category navigation

The Markdown report SHALL retain **existing** navigational elements from v1.0.0: **summary** counts with **[Ax](category-url)** links and per-finding **Category link:** **`[OWASP Ax](category-url)`**.

#### Scenario: Category link still present per finding

- **WHEN** the Markdown report is generated for any non-empty scan
- **THEN** each finding section includes a line equivalent to **Category link** with a Markdown link to the correct **OWASP Top 10:2025** page for that finding's `owasp.id`

### Requirement: JSON schema unchanged

The findings JSON **`schema_version`** SHALL remain **`1.0`**. No new **required** JSON fields SHALL be added solely for this change.

#### Scenario: Schema version stable

- **WHEN** `owasp_scan` returns a result after this change
- **THEN** `schema_version` is **`1.0`**

### Requirement: Rulepack unchanged

The **`scan.rulepack_version`** SHALL remain **`2025.1`** for this release unless a separate change updates rule content.

#### Scenario: Rulepack still 2025.1

- **WHEN** a scan completes
- **THEN** `scan.rulepack_version` is **`2025.1`**

