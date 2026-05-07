## Why

Solo developers and agents increasingly harden **HTTP APIs**, not only traditional web apps. [OWASP API Security Top 10 (2023)](https://owasp.org/www-project-api-security/) is the canonical API-focused list, but it uses **API1–API10** and different semantics than **OWASP Top 10:2025 (A01–A10)**. The MCP should surface API Security guidance **without** abandoning the existing A01–A10 contract, **without** dynamic testing, and with **honest** static limits.

## What Changes

- **Crosswalk (approach A):** Findings and Markdown reports MAY include **API Security 2023** context: short prose where useful, plus **canonical project/category links** in `references` (or subsection in Markdown) so readers can navigate from a static finding to the official API list.
- **Structured tagging (approach B):** JSON findings MAY include an **optional** `owasp_api` object (e.g. `year: 2023`, `id: "API3"`) when maintainers map a rule to a **single** official API category. Omitted when there is no defensible mapping.
- **Primary taxonomy unchanged:** Every finding **continues** to carry **`owasp`: { year: 2025, id: A01–A10 }** for filtering, sorting, and backward compatibility. **`categories`** tool parameters and caps validation remain **A01–A10 only** in v1 (no new filter for API ids unless explicitly deferred to a follow-up).
- **Static-only preserved:** No new subprocess scanners, no outbound network for core scan; link targets are **bundled constants** or stable OWASP URLs, not live fetches.
- **Rulepack maintenance:** Documented **rule_id → optional owasp_api** (and optional extra reference URLs) in the builtin rulepack; deterministic `finding.id` rules stay tied to existing key material (no churn from adding optional metadata alone).
- **Cheat Sheet Series:** Where maintainers map a rule to API-relevant guidance, the bundled **OWASP Cheat Sheet Series** map SHALL be extended so **`#### Cheat sheet`** (and the same resolver used for Markdown) can surface technology-appropriate sheets (e.g. [**GraphQL**](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)), **offline**, with **rule-first** precedence; an **optional** fallback from **`owasp_api.id`** MAY supply sheets when **`rule_id`** has no dedicated list (documented per **`design.md`**).

## Capabilities

### New Capabilities

- (none — behavior extends the existing MCP finding and report contract)

### Modified Capabilities

- `owasp-top10-mcp`: Extend finding JSON and Markdown report behavior with **optional OWASP API Security Top 10:2023** crosswalk (`references`, optional `owasp_api`); extend **bundled cheat sheet** resolution for **API- and technology-relevant** sheets when curated; clarify Purpose that API Security is **cross-mapped**, not a second primary taxonomy in v1; bump shipped **product version** as part of release hygiene.

## Impact

- **Code:** `owasp_top10_mcp/scan/finding.py`, `constants.py`, `markdown.py`, `cheat_sheets.py` (or parallel map), `rules_builtin.py` / engine reminders, tests and fixtures, `README.md` user-facing notes.
- **Specs:** Canonical `openspec/specs/owasp-top10-mcp/spec.md` gains requirements for optional `owasp_api`, reference ordering, and report subsection rules.
- **Consumers:** JSON clients may read `owasp_api` when present; existing clients ignoring unknown fields remain valid.
