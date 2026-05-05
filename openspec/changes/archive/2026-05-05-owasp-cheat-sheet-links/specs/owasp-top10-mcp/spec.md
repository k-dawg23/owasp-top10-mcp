## REMOVED Requirements

### Requirement: Product version 1.0.2

**Reason:** Superseded by **product version 1.0.4** (**OWASP cheat sheet** links). If the canonical spec already lists **1.0.3**, remove **### Requirement: Product version 1.0.3** instead during merge; only **one** product version requirement SHALL remain.

**Migration:** Expect **`scan.product_version` `1.0.4`** after this change ships.

## ADDED Requirements

### Requirement: Product version 1.0.4

The shipped package and scan metadata SHALL report **product version `1.0.4`** wherever **product version** is exposed (`pyproject.toml`, package `__version__`, and `scan.product_version` in JSON output).

#### Scenario: Scan metadata shows 1.0.4

- **WHEN** a scan completes successfully via any tool that includes scan metadata
- **THEN** the JSON envelope includes `scan.product_version` with value **`1.0.4`**

### Requirement: Bundled OWASP cheat sheet map

The system SHALL ship a **static**, read-only **cheat sheet map** bundled with the package (implementation-defined path under `owasp_top10_mcp/`). The map SHALL resolve **zero or more** cheat sheet entries (`title`, `url`) for a given finding using **`rule_id`** first, then an optional **fallback** by **`owasp.id`** (A01-A10) when no rule-specific entry exists. Resolution MUST NOT use network I/O at scan time. URLs SHOULD target **OWASP Cheat Sheet Series** or other maintainer-approved OWASP documentation pages.

#### Scenario: Offline resolution

- **WHEN** a scan runs with no network access
- **THEN** any cheat sheet links emitted in reports come only from the bundled map

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
