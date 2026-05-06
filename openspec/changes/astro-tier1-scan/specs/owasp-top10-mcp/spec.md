## REMOVED Requirements

### Requirement: Product version 1.0.4

**Reason:** Superseded by **product version 1.0.5** (Astro **`.astro`** tier-1 scanning and documentation).

**Migration:** Expect **`scan.product_version`** **`1.0.5`** after upgrade.

## ADDED Requirements

### Requirement: Product version 1.0.5

The shipped package and scan metadata SHALL report **product version `1.0.5`** wherever **product version** is exposed (`pyproject.toml`, package `__version__`, and `scan.product_version` in JSON output).

#### Scenario: Scan metadata shows 1.0.5

- **WHEN** a scan completes successfully via any tool that includes scan metadata
- **THEN** the JSON envelope includes `scan.product_version` with value **`1.0.5`**

## MODIFIED Requirements

### Requirement: Language depth tiers

The system SHALL apply **tier-1** analysis depth to **Python** and **JavaScript/TypeScript** source files, **including Astro components** with extension **`.astro`** (treated as tier-1 **SFC-style** web files alongside extensions such as **`.vue`** and **`.svelte`**), using the **same tier-1 JavaScript/TypeScript-oriented rule path** as for those extensions **where implemented**. The system SHALL apply **best-effort** analysis to **other** languages using generic or lighter-weight checks. The scan metadata MUST indicate the active tiers (implementation-defined field).

#### Scenario: Python and TypeScript get deeper rules

- **WHEN** a scan encounters `.py` and `.ts` files under the repository root
- **THEN** tier-1 rules apply to those files and the scan metadata reports tier-1 coverage for Python and JavaScript/TypeScript

#### Scenario: Astro components get tier-1 web rules

- **WHEN** a scan encounters a **`.astro`** file under the repository root that is eligible per walker rules (not gitignored, within caps)
- **THEN** tier-1 rules apply to that file using the same JavaScript/TypeScript tier-1 analysis path used for **`.vue`** / **`.svelte`** tier-1 files **where implemented**, and findings MAY include rule hits driven by content in the **`.astro`** file (e.g. existing DOM or script-oriented heuristics)
