"""Bundled OWASP Cheat Sheet Series links (curator-maintained, offline).

Maps ``rule_id`` (from ``rules_builtin``) to one or more ``{title, url}`` entries.
When a rule has no entry, :func:`resolve_cheat_sheets` falls back to a single
category-level sheet per ``owasp.id`` (A01–A10).

URLs are taken from https://cheatsheetseries.owasp.org/ (and sibling OWASP docs).
They may need periodic review for link rot; there is no runtime fetch.
"""

from __future__ import annotations

from typing import TypedDict

from owasp_top10_mcp.constants import normalize_doc_url


class CheatSheetLink(TypedDict):
    title: str
    url: str


def _link(title: str, path: str) -> CheatSheetLink:
    return {
        "title": title,
        "url": f"https://cheatsheetseries.owasp.org/cheatsheets/{path}",
    }


# rule_id -> cheat sheet links (rule-specific first; order preserved per rule)
RULE_CHEAT_SHEETS: dict[str, list[CheatSheetLink]] = {
    "owasp2025.a02.docker.from-latest": [
        _link(
            "OWASP Cheat Sheet - Docker Security",
            "Docker_Security_Cheat_Sheet.html",
        )
    ],
    "owasp2025.a02.docker.from-unpinned": [
        _link(
            "OWASP Cheat Sheet - Docker Security",
            "Docker_Security_Cheat_Sheet.html",
        )
    ],
    "owasp2025.a02.docker.no-user": [
        _link(
            "OWASP Cheat Sheet - Docker Security",
            "Docker_Security_Cheat_Sheet.html",
        )
    ],
    "owasp2025.a02.compose.privileged": [
        _link(
            "OWASP Cheat Sheet - Docker Security",
            "Docker_Security_Cheat_Sheet.html",
        )
    ],
    "owasp2025.a03.npm.non-registry-source": [
        _link(
            "OWASP Cheat Sheet - Vulnerable Dependency Management",
            "Vulnerable_Dependency_Management_Cheat_Sheet.html",
        )
    ],
    "owasp2025.a03.npm.no-lockfile": [
        _link(
            "OWASP Cheat Sheet - Vulnerable Dependency Management",
            "Vulnerable_Dependency_Management_Cheat_Sheet.html",
        )
    ],
    "owasp2025.a03.pip.unpinned": [
        _link(
            "OWASP Cheat Sheet - Vulnerable Dependency Management",
            "Vulnerable_Dependency_Management_Cheat_Sheet.html",
        )
    ],
    "owasp2025.a04.python.weak-hash": [
        _link(
            "OWASP Cheat Sheet - Cryptographic Storage",
            "Cryptographic_Storage_Cheat_Sheet.html",
        )
    ],
    "owasp2025.a04.js.weak-hash": [
        _link(
            "OWASP Cheat Sheet - Cryptographic Storage",
            "Cryptographic_Storage_Cheat_Sheet.html",
        )
    ],
    "owasp2025.a05.python.dynamic-exec": [
        _link(
            "OWASP Cheat Sheet - Injection Prevention",
            "Injection_Prevention_Cheat_Sheet.html",
        )
    ],
    "owasp2025.a05.python.sql-string-format": [
        _link(
            "OWASP Cheat Sheet - SQL Injection Prevention",
            "SQL_Injection_Prevention_Cheat_Sheet.html",
        )
    ],
    "owasp2025.a05.js.inner-html": [
        _link(
            "OWASP Cheat Sheet - XSS Prevention",
            "Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        )
    ],
    "owasp2025.a05.react.dangerous-inner": [
        _link(
            "OWASP Cheat Sheet - XSS Prevention",
            "Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        )
    ],
    "owasp2025.a05.js.eval": [
        _link(
            "OWASP Cheat Sheet - Injection Prevention",
            "Injection_Prevention_Cheat_Sheet.html",
        )
    ],
    "owasp2025.a05.html.target-blank-no-opener": [
        _link(
            "OWASP Cheat Sheet - XSS Prevention",
            "Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        )
    ],
    "owasp2025.a07.possible-hardcoded-secret": [
        _link(
            "OWASP Cheat Sheet - Secrets Management",
            "Secrets_Management_Cheat_Sheet.html",
        )
    ],
    "owasp2025.a08.python.pickle": [
        _link(
            "OWASP Cheat Sheet - Deserialization",
            "Deserialization_Cheat_Sheet.html",
        )
    ],
    "owasp2025.a08.python.yaml-load": [
        _link(
            "OWASP Cheat Sheet - Deserialization",
            "Deserialization_Cheat_Sheet.html",
        )
    ],
    "owasp2025.a10.python.broad-except": [
        _link(
            "OWASP Cheat Sheet - Error Handling",
            "Error_Handling_Cheat_Sheet.html",
        )
    ],
}

# When ``rule_id`` is not in ``RULE_CHEAT_SHEETS``, use these per OWASP 2025 id.
CATEGORY_FALLBACK: dict[str, list[CheatSheetLink]] = {
    "A01": [
        _link(
            "OWASP Cheat Sheet - Authorization",
            "Authorization_Cheat_Sheet.html",
        )
    ],
    "A02": [
        _link(
            "OWASP Cheat Sheet - Configuration Security",
            "Configuration_Security_Cheat_Sheet.html",
        )
    ],
    "A03": [
        _link(
            "OWASP Cheat Sheet - Vulnerable Dependency Management",
            "Vulnerable_Dependency_Management_Cheat_Sheet.html",
        )
    ],
    "A04": [
        _link(
            "OWASP Cheat Sheet - Cryptographic Storage",
            "Cryptographic_Storage_Cheat_Sheet.html",
        )
    ],
    "A05": [
        _link(
            "OWASP Cheat Sheet - Injection Prevention",
            "Injection_Prevention_Cheat_Sheet.html",
        )
    ],
    "A06": [
        _link(
            "OWASP Cheat Sheet - Threat Modeling",
            "Threat_Modeling_Cheat_Sheet.html",
        )
    ],
    "A07": [
        _link(
            "OWASP Cheat Sheet - Authentication",
            "Authentication_Cheat_Sheet.html",
        )
    ],
    "A08": [
        _link(
            "OWASP Cheat Sheet - Deserialization",
            "Deserialization_Cheat_Sheet.html",
        )
    ],
    "A09": [
        _link(
            "OWASP Cheat Sheet - Logging",
            "Logging_Cheat_Sheet.html",
        )
    ],
    "A10": [
        _link(
            "OWASP Cheat Sheet - Error Handling",
            "Error_Handling_Cheat_Sheet.html",
        )
    ],
}


def _dedupe_preserve_order(links: list[CheatSheetLink]) -> list[CheatSheetLink]:
    seen: set[str] = set()
    out: list[CheatSheetLink] = []
    for link in links:
        key = normalize_doc_url(link["url"])
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(link)
    return out


def resolve_cheat_sheets(rule_id: str, owasp_id: str) -> list[CheatSheetLink]:
    """Return cheat sheet links for a finding (rule-specific first, else category).

    Deduplicates by normalized URL. Category fallback is used only when there is
    no rule-specific entry in :data:`RULE_CHEAT_SHEETS`.
    """
    specific = RULE_CHEAT_SHEETS.get(rule_id)
    if specific:
        return _dedupe_preserve_order(list(specific))
    return _dedupe_preserve_order(list(CATEGORY_FALLBACK.get(owasp_id, [])))
