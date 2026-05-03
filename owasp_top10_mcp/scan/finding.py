from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from owasp_top10_mcp.constants import PATCH_CANDIDATE_ALLOWLIST, owasp_top10_url


def normalize_snippet(snippet: str) -> str:
    s = snippet.strip()
    s = re.sub(r"\s+", " ", s)
    return s


def finding_id(
    rulepack_version: str,
    rule_id: str,
    rel_path_posix: str,
    start_line: int,
    end_line: int,
    snippet: str,
) -> str:
    key = "|".join(
        (
            rulepack_version,
            rule_id,
            rel_path_posix,
            str(start_line),
            str(end_line),
            normalize_snippet(snippet),
        )
    )
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


@dataclass
class RawFinding:
    rule_id: str
    owasp_id: str
    title: str
    description: str
    severity: str
    confidence: str
    path_posix: str
    start_line: int
    end_line: int
    snippet: str
    references: list[str] = field(default_factory=list)
    fix_class: str = "unknown"
    behavior_change: bool = False
    blast_radius: str = "single_file"
    patch_candidate: bool = False
    limitations: list[str] = field(default_factory=list)
    cwe: list[int] | None = None

    def to_final_dict(self, rulepack_version: str) -> dict[str, Any]:
        patch = bool(self.patch_candidate and self.rule_id in PATCH_CANDIDATE_ALLOWLIST)
        fix_class = self.fix_class
        behavior_change = self.behavior_change
        if fix_class == "sensitive":
            patch = False
        if patch:
            fix_class = "mechanical"
            behavior_change = False
        fid = finding_id(
            rulepack_version,
            self.rule_id,
            self.path_posix,
            self.start_line,
            self.end_line,
            self.snippet,
        )
        refs = list(self.references)
        if not refs:
            refs = [owasp_top10_url(self.owasp_id)]
        out: dict[str, Any] = {
            "id": fid,
            "rule_id": self.rule_id,
            "owasp": {"year": 2025, "id": self.owasp_id},
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "location": {
                "path": self.path_posix,
                "start_line": self.start_line,
                "end_line": self.end_line,
            },
            "evidence": {"snippet": self.snippet[:2000]},
            "references": refs,
            "patch_candidate": patch,
            "fix_class": fix_class,
            "behavior_change": behavior_change,
            "blast_radius": self.blast_radius,
        }
        if self.cwe:
            out["cwe"] = self.cwe
        if self.limitations:
            out["limitations"] = self.limitations
        return out


def enforce_invariants_on_dict(f: dict[str, Any]) -> dict[str, Any]:
    """Final pass: spec invariants on serialized output."""
    if f.get("patch_candidate"):
        f["fix_class"] = "mechanical"
        f["behavior_change"] = False
    if f.get("fix_class") == "sensitive":
        f["patch_candidate"] = False
    return f
