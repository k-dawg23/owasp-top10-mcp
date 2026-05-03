"""Run static scan: file enumeration, caps, rule execution, output envelope."""

from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Any

from owasp_top10_mcp import RULEPACK_VERSION
from owasp_top10_mcp.constants import PRODUCT_VERSION, owasp_top10_url
from owasp_top10_mcp.scan.caps import (
    SEVERITY_RANK,
    merge_caps,
    normalize_categories,
    parse_profile,
    passes_severity_floor,
)
from owasp_top10_mcp.scan.finding import enforce_invariants_on_dict
from owasp_top10_mcp.scan.rules_builtin import _rf, run_rules_on_file
from owasp_top10_mcp.scan.walker import iter_eligible_files


def _sort_key(f: dict[str, Any]) -> tuple[int, str, int]:
    sev = f.get("severity", "info")
    rank = SEVERITY_RANK.get(sev, 99)
    loc = f.get("location", {})
    path = loc.get("path", "")
    line = int(loc.get("start_line", 0))
    return (rank, path, line)


def run_scan(
    repo_root: str,
    categories: list[str] | None = None,
    profile: str = "agent_quick",
    max_files: int | None = None,
    max_bytes_per_file: int | None = None,
    max_total_bytes: int | None = None,
    time_budget_ms: int | None = None,
    severity_floor: str | None = None,
) -> dict[str, Any]:
    root = Path(repo_root).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(
            f"repo_root is not an existing directory: {repo_root!r} (resolved: {root})"
        )

    cats = normalize_categories(categories)
    base = parse_profile(profile)
    caps = merge_caps(
        base,
        max_files=max_files,
        max_bytes_per_file=max_bytes_per_file,
        max_total_bytes=max_total_bytes,
        time_budget_ms=time_budget_ms,
        severity_floor=severity_floor,
    )

    t0 = time.perf_counter()
    run_id = str(uuid.uuid4())
    truncation_reasons: list[str] = []
    partial_file_reads = False
    files_scanned = 0
    bytes_read = 0
    raw_findings: list[RawFinding] = []
    seen_rule_loc: set[tuple[str, str, int]] = set()
    tier1_hits = 0

    file_list = iter_eligible_files(root)
    hit_file_cap = False
    hit_byte_cap = False
    hit_time = False

    for full_path, rel_posix, tier in file_list:
        elapsed_ms = (time.perf_counter() - t0) * 1000
        if elapsed_ms >= caps.time_budget_ms:
            hit_time = True
            truncation_reasons.append("time_budget_ms")
            break
        if files_scanned >= caps.max_files:
            hit_file_cap = True
            truncation_reasons.append("max_files")
            break
        if bytes_read >= caps.max_total_bytes:
            hit_byte_cap = True
            truncation_reasons.append("max_total_bytes")
            break

        try:
            size = full_path.stat().st_size
        except OSError:
            continue
        to_read = min(size, caps.max_bytes_per_file)
        if bytes_read + to_read > caps.max_total_bytes:
            hit_byte_cap = True
            truncation_reasons.append("max_total_bytes")
            break

        try:
            data = full_path.read_bytes()[: caps.max_bytes_per_file]
        except OSError:
            continue

        if len(data) < size:
            partial_file_reads = True

        text = data.decode("utf-8", errors="replace")
        bytes_read += len(data)
        files_scanned += 1

        if tier == "tier1":
            tier1_hits += 1

        for rf in run_rules_on_file(root, rel_posix, tier, text):
            key = (rf.rule_id, rf.path_posix, rf.start_line)
            if key in seen_rule_loc:
                continue
            seen_rule_loc.add(key)
            raw_findings.append(rf)

    if partial_file_reads:
        truncation_reasons.append("max_bytes_per_file")
    truncated = bool(truncation_reasons) or hit_file_cap or hit_byte_cap or hit_time

    # One holistic A06 + A01 review nudge if we saw application code
    if tier1_hits > 0:
        raw_findings.append(
            _rf(
                "owasp2025.a06.threat-model-reminder",
                "A06",
                "Manual review: threat modeling and abuse cases",
                "Automated rules cannot validate overall design; consider STRIDE/abuse cases for privileged actions.",
                "medium",
                "review_required",
                ".",
                1,
                "(scan-wide reminder)",
                references=[owasp_top10_url("A06")],
                fix_class="unknown",
                behavior_change=False,
                blast_radius="repo",
            )
        )
        raw_findings.append(
            _rf(
                "owasp2025.a01.authz-review-reminder",
                "A01",
                "Manual review: authorization and object access",
                "Verify every sensitive operation checks ownership/tenant and appropriate role (IDOR/BAC).",
                "medium",
                "review_required",
                ".",
                1,
                "(scan-wide reminder)",
                references=[owasp_top10_url("A01")],
                fix_class="unknown",
                behavior_change=False,
                blast_radius="repo",
            )
        )

    final: list[dict[str, Any]] = []
    for rf in raw_findings:
        fd = rf.to_final_dict(RULEPACK_VERSION)
        fd = enforce_invariants_on_dict(fd)
        if not passes_severity_floor(fd["severity"], caps.severity_floor):
            continue
        if cats is not None and fd["owasp"]["id"] not in cats:
            continue
        final.append(fd)

    final.sort(key=_sort_key)

    time_ms = int((time.perf_counter() - t0) * 1000)

    scan_meta: dict[str, Any] = {
        "rulepack_version": RULEPACK_VERSION,
        "product_version": PRODUCT_VERSION,
        "run_id": run_id,
        "profile": profile.strip().lower(),
        "truncated": truncated,
        "truncation_reasons": list(dict.fromkeys(truncation_reasons)),
        "time_ms": time_ms,
        "limits_applied": {
            "max_files": caps.max_files,
            "max_bytes_per_file": caps.max_bytes_per_file,
            "max_total_bytes": caps.max_total_bytes,
            "time_budget_ms": caps.time_budget_ms,
            "severity_floor": caps.severity_floor,
        },
        "files_scanned": files_scanned,
        "bytes_read": bytes_read,
        "language_tiers": {
            "python_javascript_typescript": "tier1",
            "other_extensions": "best_effort",
            "repo_context": "context",
        },
    }

    return {
        "schema_version": "1.0",
        "scan": scan_meta,
        "findings": final,
    }
