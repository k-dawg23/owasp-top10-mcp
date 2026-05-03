from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from owasp_top10_mcp.constants import (
    OWASP_2025_SLUGS,
    cwe_url,
    normalize_doc_url,
    owasp_top10_url,
)
from owasp_top10_mcp.scan.caps import SEVERITY_RANK


SEVERITY_ORDER_LABELS = list(SEVERITY_RANK.keys())
SEVERITY_ORDER_LABELS.sort(key=lambda k: SEVERITY_RANK[k])


def _reference_link_label(url: str) -> str:
    n = normalize_doc_url(url)
    for ax in sorted(OWASP_2025_SLUGS.keys()):
        if n == normalize_doc_url(owasp_top10_url(ax)):
            return f"OWASP Top 10:2025 - {ax}"
    parsed = urlparse(url.strip())
    host = parsed.netloc or ""
    path = (parsed.path or "").rstrip("/")
    if host and path:
        return f"{host}{path}"
    if host:
        return host
    return "Documentation"


def _supplementary_references(
    references: list[str], category_url_norm: str
) -> list[str]:
    seen_set: set[str] = set()
    out: list[str] = []
    for raw in references:
        n = normalize_doc_url(raw)
        if not n or n == category_url_norm:
            continue
        if n in seen_set:
            continue
        seen_set.add(n)
        out.append(raw)
    return out


def render_markdown(envelope: dict[str, Any]) -> str:
    scan = envelope.get("scan", {})
    findings = envelope.get("findings", [])
    lines: list[str] = []
    lines.append("# OWASP Top 10 oriented scan report")
    lines.append("")
    lines.append(f"- **Rulepack:** `{scan.get('rulepack_version', '')}`")
    lines.append(f"- **Product:** `{scan.get('product_version', '')}`")
    lines.append(f"- **Profile:** `{scan.get('profile', '')}`")
    lines.append(f"- **Run id:** `{scan.get('run_id', '')}`")
    lines.append(f"- **Time (ms):** {scan.get('time_ms', 0)}")
    lines.append(f"- **Files scanned:** {scan.get('files_scanned', 0)}")
    lines.append(f"- **Bytes read:** {scan.get('bytes_read', 0)}")
    lim = scan.get("limits_applied", {})
    lines.append(
        f"- **Limits:** max_files={lim.get('max_files')} max_bytes_per_file={lim.get('max_bytes_per_file')} "
        f"max_total_bytes={lim.get('max_total_bytes')} time_budget_ms={lim.get('time_budget_ms')} "
        f"severity_floor={lim.get('severity_floor')}"
    )
    if scan.get("truncated"):
        lines.append(f"- **TRUNCATED:** {', '.join(scan.get('truncation_reasons', []))}")
    lines.append("")
    lines.append("## Summary counts")
    by_sev: dict[str, int] = {}
    by_cat: dict[str, int] = {}
    for f in findings:
        by_sev[f.get("severity", "unknown")] = by_sev.get(f.get("severity"), 0) + 1
        oid = f.get("owasp", {}).get("id", "?")
        by_cat[oid] = by_cat.get(oid, 0) + 1
    lines.append("### By severity")
    for s in SEVERITY_ORDER_LABELS:
        if s in by_sev:
            lines.append(f"- **{s}:** {by_sev[s]}")
    lines.append("")
    lines.append("### By OWASP category (2025)")
    for k in sorted(by_cat.keys()):
        url = owasp_top10_url(k)
        lines.append(f"- **[{k}]({url}):** {by_cat[k]}")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    lines.append(
        "Sort order matches JSON: **severity** (critical first), then **path**, then **start_line**."
    )
    lines.append("")
    for f in findings:
        loc = f.get("location", {})
        oid = f.get("owasp", {}).get("id", "?")
        url = owasp_top10_url(oid)
        lines.append(
            f"### [{f.get('id', '')[:16]}…] {f.get('title', '')} — **{oid}** / {f.get('severity', '')}"
        )
        lines.append("")
        lines.append(f"- **Rule:** `{f.get('rule_id', '')}`")
        lines.append(f"- **Confidence:** {f.get('confidence', '')}")
        lines.append(
            f"- **Location:** `{loc.get('path', '')}` lines {loc.get('start_line')}-{loc.get('end_line')}"
        )
        lines.append(f"- **Category link:** [OWASP {oid}]({url})")
        cat_norm = normalize_doc_url(url)
        cwes = f.get("cwe") or []
        if cwes:
            lines.append("")
            lines.append("#### CWE")
            lines.append("")
            for cid in cwes:
                cu = cwe_url(int(cid))
                lines.append(f"- [CWE-{int(cid)}]({cu})")
        refs = f.get("references") or []
        if isinstance(refs, list):
            extra = _supplementary_references([str(x) for x in refs], cat_norm)
            if extra:
                lines.append("")
                lines.append("#### Further reading")
                lines.append("")
                for r in extra:
                    label = _reference_link_label(r)
                    lines.append(f"- [{label}]({r})")
        ev = f.get("evidence", {})
        snippet = ev.get("snippet", "")
        if snippet:
            lines.append("")
            lines.append("```")
            lines.append(snippet[:800])
            lines.append("```")
        lines.append("")
        lines.append(f"{f.get('description', '')}")
        lim = f.get("limitations")
        if lim:
            lines.append("")
            lines.append(f"*Limitations:* {', '.join(lim)}")
        lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("*v1 does not generate PDF; export this Markdown externally if needed.*")
    return "\n".join(lines)
