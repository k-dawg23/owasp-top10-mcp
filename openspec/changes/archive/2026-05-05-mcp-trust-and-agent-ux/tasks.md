## 1. Specification

- [x] 1.1 Update **`openspec/specs/owasp-top10-mcp/spec.md`**: set **`## Purpose`** to prose consistent with **`design.md` D1**; ensure delta **MODIFIED** / **ADDED** requirements match after merge (run **`openspec archive`** for this change when implementation is done, or apply delta per workflow).
- [x] 1.2 Run **`openspec validate mcp-trust-and-agent-ux`** and fix any spec formatting issues.

## 2. README

- [x] 2.1 Add **Which tool to use** (or equivalent) section: **`owasp_scan`**, **`owasp_report`**, **`owasp_report_save`** with one-line primary uses; point to MCP reload after local upgrade if not already adjacent.

## 3. MCP tool descriptions

- [x] 3.1 Update **`owasp_top10_mcp/server.py`** docstrings for **`owasp_scan`**, **`owasp_report`**, and **`owasp_report_save`** so they match **`design.md` D4** and satisfy the **Client-agnostic** / **tool choice** scenarios (portable language, when to use each).

## 4. Sanity check

- [x] 4.1 Quick manual smoke: start server or import tools; optional **`pytest`** if a tiny test was added for docstring presence or keywords.
