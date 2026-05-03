## 1. Version bump

- [x] 1.1 Set **product version** to **1.0.1** in `pyproject.toml` and `owasp_top10_mcp/__init__.py` (and `README.md` if it states version explicitly).

## 2. CWE URL helper

- [x] 2.1 Add a small helper (e.g. in `constants.py` or `scan/markdown.py`) `cwe_url(cwe_id: int) -> str` returning `https://cwe.mitre.org/data/definitions/{id}.html`.

## 3. Markdown renderer

- [x] 3.1 For each finding in `render_markdown`, if `cwe` is non-empty, render a **CWE** subsection with `[CWE-{id}](url)` links (or equivalent readable labels per `design.md` D1).
- [x] 3.2 Add **Further reading** subsection listing each **distinct** `references` URL as a Markdown link; apply **label** rules per `design.md` D2 and **dedupe** per D3.
- [x] 3.3 Keep **summary** and **Category link** lines per spec (v1.0.0 behavior preserved).

## 4. Tests

- [x] 4.1 Extend tests to assert Markdown contains MITRE CWE URL for a fixture finding that includes `cwe`.
- [x] 4.2 Assert **Further reading** includes a Markdown link for supplementary `references` URLs (category-only references omit the section per D3).
- [x] 4.3 Assert `schema_version` remains `1.0`, `rulepack_version` **`2025.1`**, and `product_version` is **`1.0.1`** after bump.

## 5. Documentation

- [x] 5.1 Note **v1.0.1** report improvements (CWE + Further reading) in `README.md` under a short **Changelog** or **Release notes** bullet.
