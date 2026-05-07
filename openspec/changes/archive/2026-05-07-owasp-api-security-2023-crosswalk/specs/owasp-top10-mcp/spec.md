## MODIFIED Requirements

### Requirement: Specification purpose in canonical spec

The **Purpose** section of this file SHALL describe the intended audience (**solo developers and AI agents**), **stdio** MCP transport, **static** OWASP Top 10:2025 scope (**A01–A10**) as the **primary** finding taxonomy, **supplementary** linkage to **OWASP API Security Top 10:2023** (**API1–API10**) where **optional** metadata and **bundled** references are provided, **local** operation without **requiring PyPI** for end users, and **advisory** findings (no mandatory hosted service for core operation).

#### Scenario: Purpose is substantive

- **WHEN** a reader opens this specification file after this change is applied
- **THEN** the **Purpose** section is concrete prose and does not consist solely of a **`TBD`** placeholder

### Requirement: Finding object contract

Each finding object SHALL include at minimum: **`id`**, **`rule_id`**, **`owasp`** (`year` **2025**, `id` **A01–A10**), **`title`**, **`description`**, **`severity`**, **`confidence`** (one of `rule` | `heuristic` | `review_required` or an equivalent documented enum), **`location`** (path and line range), **`evidence`** (short snippet), **`references`** (OWASP Top 10 category link encouraged; **additional** OWASP API Security documentation URLs allowed when static maps provide them), **`patch_candidate`** (boolean), **`fix_class`**, **`behavior_change`** (boolean), and **`blast_radius`**. Optional **`cwe`**, **`limitations`**, and **`owasp_api`** MAY be included.

When present, **`owasp_api`** SHALL be an object with **`year`** **`2023`** and **`id`** one of **`API1`** through **`API10`** (string labels exactly as used in OWASP API Security Top 10:2023 documentation). It MUST be omitted when the rulepack does not define a **documented** mapping for that finding.

The **`id`** SHALL be a **deterministic SHA-256** (**64-character lowercase hexadecimal**) computed from the **canonical key** in **`design.md`** (which MUST NOT include **`owasp_api`** or API reference URLs). The system MUST NOT use **UUIDs** for finding **`id`** in v1.

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

## REMOVED Requirements

### Requirement: Product version 1.0.5

**Reason:** Superseded by **product version 1.0.6** (**OWASP API Security 2023 crosswalk**).

**Migration:** Expect **`scan.product_version` `1.0.6`** after this change ships.

## ADDED Requirements

### Requirement: Product version 1.0.6

The shipped package and scan metadata SHALL report **product version `1.0.6`** wherever **product version** is exposed (`pyproject.toml`, package `__version__`, and `scan.product_version` in JSON output).

#### Scenario: Scan metadata shows 1.0.6

- **WHEN** a scan completes successfully via any tool that includes scan metadata
- **THEN** the JSON envelope includes `scan.product_version` with value **`1.0.6`**

### Requirement: Bundled OWASP API Security 2023 URL map

The system SHALL ship a **static** map bundled with the package (under `owasp_top10_mcp/`, implementation-defined module) from each allowed **`owasp_api.id`** (**API1**–**API10**) to **one** canonical documentation URL for that **2023** category (or to the **OWASP API Security project hub** when a stable per-category URL is not maintained). The system SHALL also define a **hub** URL for the project (e.g. `https://owasp.org/www-project-api-security/`). Resolution MUST NOT use network I/O at scan time.

#### Scenario: Offline API link resolution

- **WHEN** a scan runs with no network access
- **THEN** any API Security documentation URLs emitted in **`references`** or Markdown come only from the bundled map or from explicitly constructed strings defined beside that map in source

### Requirement: Primary category filter unchanged

The **`categories`** (or equivalent) parameter on **`owasp_scan`**, **`owasp_report`**, **`owasp_report_save`**, and **`owasp_scan_save`** SHALL accept **only** **A01–A10** in v1. **`owasp_api`** MUST NOT be accepted as a filter key in v1.

#### Scenario: Agent passes only A01–A10

- **WHEN** a client supplies category filters
- **THEN** invalid category strings (including **API1**–**API10**) are rejected or ignored per existing validation behavior for unknown categories, without changing the **A01–A10** contract

### Requirement: Markdown OWASP API Security subsection

For each finding, when the serialized finding includes **`owasp_api`** **or** when **`references`** includes at least one URL that resolves (per implementation-defined normalization) to an **OWASP API Security** documentation URL from the bundled map, the Markdown report SHALL include **`#### OWASP API Security (2023)`** with a Markdown bullet list of **distinct** **`[title](url)`** links. The **category** link for the finding’s **`owasp_api.id`**, when present, SHOULD appear before the **hub** link. When **`owasp_api`** is absent and no such **`references`** URL exists, the subsection MUST be omitted entirely.

#### Scenario: Mapped finding shows API subsection

- **WHEN** a finding includes **`owasp_api`** with **`id`** **`API3`**
- **THEN** the Markdown for that finding includes **`#### OWASP API Security (2023)`** and at least one link drawn from the bundled map

#### Scenario: Unmapped finding omits API subsection

- **WHEN** a finding has no **`owasp_api`** and no API Security URLs in **`references`**
- **THEN** the Markdown for that finding does not include **`#### OWASP API Security (2023)`**

### Requirement: Cheat sheet resolution with API and technology supplements

The resolver that produces **`#### Cheat sheet`** links SHALL follow this **precedence** (first match wins for populating the list before deduplication): **`rule_id`** entries in the bundled **`RULE_CHEAT_SHEETS`** map; if there are **none**, **optional** bundled fallback entries keyed by **`owasp_api.id`** (**API1**–**API10**) **when** the finding includes **`owasp_api`**; if there are still **none**, the existing **A01–A10** category fallback per **Bundled OWASP cheat sheet map**. Resolution MUST NOT use network I/O at scan time.

Curators MAY add **OWASP Cheat Sheet Series** URLs (under **`https://cheatsheetseries.owasp.org/cheatsheets/`**) to **`RULE_CHEAT_SHEETS`** for **`rule_id`** values where a **technology- or API-specific** sheet is appropriate—**including** the [GraphQL cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html) when a rule targets GraphQL or related API surface.

#### Scenario: Rule maps to GraphQL cheat sheet

- **WHEN** a finding’s **`rule_id`** is listed in **`RULE_CHEAT_SHEETS`** with the **GraphQL** cheat sheet URL
- **THEN** the Markdown **`#### Cheat sheet`** subsection includes that link (subject to existing deduplication rules)

#### Scenario: owasp_api fallback applies when rule unmapped

- **WHEN** a finding includes **`owasp_api`**, has **no** **`rule_id`** entry in **`RULE_CHEAT_SHEETS`**, and the bundled **`owasp_api.id`** fallback defines one or more cheat sheets for that **`id`**
- **THEN** **`#### Cheat sheet`** includes those fallback links

#### Scenario: Category fallback unchanged when no rule or API sheets

- **WHEN** a finding has **no** **`rule_id`** cheat sheets and **no** applicable **`owasp_api.id`** fallback
- **THEN** resolution behaves as today using **`owasp.id`** (**A01–A10**) category fallback only
