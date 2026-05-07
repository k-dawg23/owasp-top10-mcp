from __future__ import annotations

from urllib.parse import urlparse

from owasp_top10_mcp import __version__

PRODUCT_VERSION = __version__

OWASP_2025_SLUGS: dict[str, str] = {
    "A01": "A01_2025-Broken_Access_Control",
    "A02": "A02_2025-Security_Misconfiguration",
    "A03": "A03_2025-Software_Supply_Chain_Failures",
    "A04": "A04_2025-Cryptographic_Failures",
    "A05": "A05_2025-Injection",
    "A06": "A06_2025-Insecure_Design",
    "A07": "A07_2025-Authentication_Failures",
    "A08": "A08_2025-Software_or_Data_Integrity_Failures",
    "A09": "A09_2025-Security_Logging_and_Alerting_Failures",
    "A10": "A10_2025-Mishandling_of_Exceptional_Conditions",
}

OWASP_API_SECURITY_HUB = "https://owasp.org/www-project-api-security/"

# OWASP API Security Top 10 2023 — edition/enGLISH category pages (stable paths per OWASP).
OWASP_API_2023_CATEGORY_URLS: dict[str, str] = {
    "API1": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
    "API2": "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
    "API3": "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
    "API4": "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
    "API5": "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
    "API6": "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
    "API7": "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
    "API8": "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
    "API9": "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
    "API10": "https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/",
}

VALID_OWASP_API_IDS: frozenset[str] = frozenset(OWASP_API_2023_CATEGORY_URLS.keys())

OWASP_API_MARKDOWN_TITLES: dict[str, str] = {
    "API1": "API1:2023 - Broken Object Level Authorization",
    "API2": "API2:2023 - Broken Authentication",
    "API3": "API3:2023 - Broken Object Property Level Authorization",
    "API4": "API4:2023 - Unrestricted Resource Consumption",
    "API5": "API5:2023 - Broken Function Level Authorization",
    "API6": "API6:2023 - Unrestricted Access to Sensitive Business Flows",
    "API7": "API7:2023 - Server Side Request Forgery",
    "API8": "API8:2023 - Security Misconfiguration",
    "API9": "API9:2023 - Improper Inventory Management",
    "API10": "API10:2023 - Unsafe Consumption of APIs",
}


def owasp_top10_url(owasp_id: str) -> str:
    slug = OWASP_2025_SLUGS.get(owasp_id)
    if not slug:
        return "https://owasp.org/Top10/2025/"
    return f"https://owasp.org/Top10/2025/{slug}/"


def owasp_api_category_url(api_id: str) -> str:
    return OWASP_API_2023_CATEGORY_URLS.get(api_id, OWASP_API_SECURITY_HUB)


def cwe_url(cwe_id: int) -> str:
    return f"https://cwe.mitre.org/data/definitions/{int(cwe_id)}.html"


def normalize_doc_url(url: str) -> str:
    """Normalize URL for dedupe (scheme and host lowercased; one trailing slash stripped from path)."""
    raw = url.strip()
    if not raw:
        return ""
    p = urlparse(raw)
    scheme = p.scheme.lower()
    netloc = p.netloc.lower()
    path = p.path or ""
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    if path == "/":
        path = ""
    return f"{scheme}://{netloc}{path}"


def is_owasp_api_security_doc_url(url: str) -> bool:
    n = normalize_doc_url(url).lower()
    return "owasp.org/api-security" in n or "owasp.org/www-project-api-security" in n


def merge_owasp_api_references(
    references: list[str], owasp_api_id: str
) -> list[str]:
    """Append API category + hub URLs not already present (normalized dedupe)."""
    refs = list(references)
    seen = {normalize_doc_url(r) for r in refs if r}
    cat_u = owasp_api_category_url(owasp_api_id)
    for u in (cat_u, OWASP_API_SECURITY_HUB):
        nu = normalize_doc_url(u)
        if nu and nu not in seen:
            refs.append(u)
            seen.add(nu)
    return refs


PATCH_CANDIDATE_ALLOWLIST: frozenset[str] = frozenset(
    {
        "owasp2025.a05.html.target-blank-no-opener",
    }
)
