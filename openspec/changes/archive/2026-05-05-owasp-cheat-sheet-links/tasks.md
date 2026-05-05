## 1. Version

- [x] 1.1 Set **product version** to **1.0.4** in `pyproject.toml`, `owasp_top10_mcp/__init__.py`, and `uv.lock` if it pins the workspace package.

## 2. Cheat sheet map

- [x] 2.1 Add bundled **static map** (module and/or JSON) with **`rule_id`** keys and optional **A01-A10** fallbacks; include entries for a first slice of high-value **`rules_builtin`** ids (expand iteratively); document URL sources in **`design.md`** or file header.
- [x] 2.2 Add pure resolver helper: `(rule_id, owasp_id) -> list[{title, url}]` with dedupe per **D4**.

## 3. Markdown

- [x] 3.1 In **`render_markdown`**, after existing finding body sections (e.g. CWE / Further reading ordering per current style), render **`#### Cheat sheet`** only when the resolver returns links.

## 4. Docs

- [x] 4.1 **README:** note **v1.0.4** cheat sheet links, limitation that URLs are **curated** and may need occasional updates, **no PyPI** required.

## 5. Tests

- [x] 5.1 Fixture or synthetic finding with a **mapped** `rule_id` asserts **`#### Cheat sheet`** and expected hostname/path in Markdown.
- [x] 5.2 Unmapped rule with no fallback omits subsection.
- [x] 5.3 Fallback-by-category scenario if implemented.
- [x] 5.4 `scan.product_version` is **`1.0.4`** in **`run_scan`** output after bump.
