from __future__ import annotations

from owasp_top10_mcp import RULEPACK_VERSION, __version__

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


def owasp_top10_url(owasp_id: str) -> str:
    slug = OWASP_2025_SLUGS.get(owasp_id)
    if not slug:
        return "https://owasp.org/Top10/2025/"
    return f"https://owasp.org/Top10/2025/{slug}/"


PATCH_CANDIDATE_ALLOWLIST: frozenset[str] = frozenset(
    {
        "owasp2025.a05.html.target-blank-no-opener",
    }
)
