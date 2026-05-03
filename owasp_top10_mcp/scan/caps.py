from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

VALID_CATEGORIES = frozenset(f"A{i:02d}" for i in range(1, 11))  # A01..A10


@dataclass
class ScanCaps:
    max_files: int
    max_bytes_per_file: int
    max_total_bytes: int
    time_budget_ms: int
    severity_floor: str  # critical|high|medium|low|info


PROFILE_DEFAULTS: dict[str, ScanCaps] = {
    "agent_quick": ScanCaps(
        max_files=1000,
        max_bytes_per_file=512_000,
        max_total_bytes=100_000_000,
        time_budget_ms=120_000,
        severity_floor="medium",
    ),
    "human_full": ScanCaps(
        max_files=5000,
        max_bytes_per_file=1_048_576,
        max_total_bytes=500_000_000,
        time_budget_ms=300_000,
        severity_floor="low",
    ),
}

SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def parse_profile(name: str) -> ScanCaps:
    key = name.strip().lower()
    if key not in PROFILE_DEFAULTS:
        raise ValueError(
            f"Unknown profile {name!r}; expected one of: {', '.join(sorted(PROFILE_DEFAULTS))}"
        )
    return PROFILE_DEFAULTS[key]


def merge_caps(base: ScanCaps, **overrides: Any) -> ScanCaps:
    d = {
        "max_files": base.max_files,
        "max_bytes_per_file": base.max_bytes_per_file,
        "max_total_bytes": base.max_total_bytes,
        "time_budget_ms": base.time_budget_ms,
        "severity_floor": base.severity_floor,
    }
    for k, v in overrides.items():
        if v is None:
            continue
        if k not in d:
            continue
        if k == "severity_floor":
            d[k] = str(v).lower()
        else:
            d[k] = int(v)
    sf = d["severity_floor"]
    if sf not in SEVERITY_RANK:
        raise ValueError(f"Invalid severity_floor {sf!r}")
    return ScanCaps(**d)


def normalize_categories(raw: list[str] | None) -> frozenset[str] | None:
    if raw is None:
        return None
    out: set[str] = set()
    for item in raw:
        c = item.strip().upper()
        m = re.match(r"^(A\d{2})", c)
        if m:
            c = m.group(1)
        if c not in VALID_CATEGORIES:
            raise ValueError(
                f"Invalid OWASP category {item!r}; expected A01–A10 (2025 implied)"
            )
        out.add(c)
    return frozenset(out)


def passes_severity_floor(severity: str, floor: str) -> bool:
    return SEVERITY_RANK.get(severity, 99) <= SEVERITY_RANK.get(floor, 99)
