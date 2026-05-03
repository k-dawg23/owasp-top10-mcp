from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath

from owasp_top10_mcp.scan.finding import RawFinding

A03_LIMIT = ["no_cve_correlation_in_v1"]


def _rf(
    rule_id: str,
    ow: str,
    title: str,
    desc: str,
    severity: str,
    conf: str,
    path: str,
    line: int,
    snippet: str,
    **kw: object,
) -> RawFinding:
    end_line = int(kw.get("end_line", line))
    return RawFinding(
        rule_id=rule_id,
        owasp_id=ow,
        title=title,
        description=desc,
        severity=severity,
        confidence=conf,
        path_posix=path,
        start_line=line,
        end_line=end_line,
        snippet=snippet.strip()[:500],
        references=list(kw["references"]) if kw.get("references") else [],
        fix_class=str(kw.get("fix_class", "unknown")),
        behavior_change=bool(kw.get("behavior_change", False)),
        blast_radius=str(kw.get("blast_radius", "single_file")),
        patch_candidate=bool(kw.get("patch_candidate", False)),
        limitations=list(kw["limitations"]) if kw.get("limitations") else [],
        cwe=list(kw["cwe"]) if kw.get("cwe") else None,
    )


def analyze_dockerfile(rel_posix: str, lines: list[str]) -> list[RawFinding]:
    out: list[RawFinding] = []
    if not lines:
        return out
    has_user = False
    for i, line in enumerate(lines, start=1):
        u = line.strip()
        ul = u.upper()
        if ul.startswith("USER ") and not ul.startswith("USER ROOT"):
            has_user = True
        if ul.startswith("FROM "):
            img = u[4:].strip().split()[0] if u[4:].strip() else ""
            if img.endswith(":latest"):
                out.append(
                    _rf(
                        "owasp2025.a02.docker.from-latest",
                        "A02",
                        "Dockerfile uses :latest tag",
                        "The :latest tag is a moving target and weakens reproducibility.",
                        "low",
                        "rule",
                        rel_posix,
                        i,
                        u,
                        fix_class="mechanical",
                        behavior_change=False,
                        limitations=A03_LIMIT,
                    )
                )
            elif img and ":" not in img:
                out.append(
                    _rf(
                        "owasp2025.a02.docker.from-unpinned",
                        "A02",
                        "Dockerfile FROM has no tag",
                        "Images without an explicit tag often default to latest.",
                        "medium",
                        "heuristic",
                        rel_posix,
                        i,
                        u,
                        fix_class="local_logic",
                        behavior_change=True,
                        blast_radius="module",
                    )
                )
    if not has_user and lines:
        out.append(
            _rf(
                "owasp2025.a02.docker.no-user",
                "A02",
                "Dockerfile does not set a non-root USER",
                "Container may run as root, increasing impact of container escapes or RCE.",
                "medium",
                "heuristic",
                rel_posix,
                len(lines),
                "(no USER directive found)",
                fix_class="local_logic",
                behavior_change=True,
                blast_radius="module",
            )
        )
    return out


def analyze_compose(rel_posix: str, text: str) -> list[RawFinding]:
    if re.search(r"privileged\s*:\s*true", text):
        return [
            _rf(
                "owasp2025.a02.compose.privileged",
                "A02",
                "docker-compose sets privileged: true",
                "Privileged containers bypass key kernel isolation.",
                "high",
                "rule",
                rel_posix,
                1,
                "privileged: true",
                fix_class="sensitive",
                behavior_change=True,
                blast_radius="repo",
            )
        ]
    return []


def analyze_package_json(rel_posix: str, text: str) -> list[RawFinding]:
    out: list[RawFinding] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return out
    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
    loose_sources = [
        k
        for k, v in deps.items()
        if isinstance(v, str) and ("git+" in v or v.startswith("file:") or v.startswith("http"))
    ]
    if loose_sources:
        out.append(
            _rf(
                "owasp2025.a03.npm.non-registry-source",
                "A03",
                "npm dependency uses non-registry tarball/git/http source",
                f"Non-registry sources increase supply-chain risk: {', '.join(loose_sources[:5])}.",
                "medium",
                "heuristic",
                rel_posix,
                1,
                text[:200],
                fix_class="local_logic",
                behavior_change=True,
                limitations=A03_LIMIT,
                blast_radius="module",
            )
        )
    return out


def analyze_requirements(rel_posix: str, lines: list[str]) -> list[RawFinding]:
    out: list[RawFinding] = []
    for i, line in enumerate(lines, start=1):
        s = line.strip()
        if not s or s.startswith("#") or s.startswith("-"):
            continue
        if " #" in s:
            s = s.split(" #")[0].strip()
        if any(x in s for x in ("==", ">=", "<=", "~=", "!=", "@")):
            continue
        if re.match(r"^[a-zA-Z0-9_.\-]+\s*$", s):
            out.append(
                _rf(
                    "owasp2025.a03.pip.unpinned",
                    "A03",
                    "Unpinned Python dependency",
                    f"Dependency {s!r} has no explicit version pin (no CVE correlation in v1).",
                    "low",
                    "heuristic",
                    rel_posix,
                    i,
                    s,
                    fix_class="mechanical",
                    behavior_change=False,
                    limitations=A03_LIMIT,
                )
            )
    return out


def analyze_lines_python_tier1(rel_posix: str, lines: list[str]) -> list[RawFinding]:
    out: list[RawFinding] = []
    joined = "\n".join(lines)
    if re.search(r"pickle\.loads?\(", joined):
        ln = next((i for i, l in enumerate(lines, 1) if "pickle.load" in l), 1)
        out.append(
            _rf(
                "owasp2025.a08.python.pickle",
                "A08",
                "Potential unsafe deserialization (pickle)",
                "pickle can execute arbitrary code on load when processing untrusted data.",
                "high",
                "heuristic",
                rel_posix,
                ln,
                lines[ln - 1][:300],
                fix_class="sensitive",
                behavior_change=True,
                cwe=[502],
            )
        )
    for i, line in enumerate(lines, start=1):
        if re.search(r"yaml\.load\([^)]*\)", line) and "SafeLoader" not in line and "safe_load" not in line:
            out.append(
                _rf(
                    "owasp2025.a08.python.yaml-load",
                    "A08",
                    "yaml.load without SafeLoader",
                    "Prefer safe_load or Loader=yaml.SafeLoader.",
                    "high",
                    "heuristic",
                    rel_posix,
                    i,
                    line.strip()[:300],
                    fix_class="local_logic",
                    behavior_change=True,
                    cwe=[502],
                )
            )
        if re.search(r"exec\s*\(|eval\s*\(", line):
            out.append(
                _rf(
                    "owasp2025.a05.python.dynamic-exec",
                    "A05",
                    "Dynamic code execution (exec/eval)",
                    "exec/eval with influenced input is frequently exploitable.",
                    "high",
                    "heuristic",
                    rel_posix,
                    i,
                    line.strip()[:300],
                    fix_class="sensitive",
                    behavior_change=True,
                    cwe=[94],
                )
            )
        if re.search(r"(\.execute\s*\(\s*f[\"']|\.execute\s*\(\s*[\"'][^\"']*\{)", line):
            out.append(
                _rf(
                    "owasp2025.a05.python.sql-string-format",
                    "A05",
                    "Possible SQL string formatting in execute()",
                    "Use bound parameters instead of interpolating into SQL strings.",
                    "high",
                    "heuristic",
                    rel_posix,
                    i,
                    line.strip()[:300],
                    fix_class="local_logic",
                    behavior_change=True,
                    cwe=[89],
                )
            )
        if re.search(r"hashlib\.(md5|sha1)\s*\(", line) and "usedforsecurity=False" not in line:
            out.append(
                _rf(
                    "owasp2025.a04.python.weak-hash",
                    "A04",
                    "Weak hash (MD5/SHA1)",
                    "MD5/SHA1 are weak for security-sensitive integrity uses.",
                    "medium",
                    "heuristic",
                    rel_posix,
                    i,
                    line.strip()[:300],
                    fix_class="local_logic",
                    behavior_change=True,
                    cwe=[328],
                )
            )
        if re.match(r"^\s*except\s*:\s*$", line) or re.match(
            r"^\s*except\s+Exception\s*:\s*$", line
        ):
            out.append(
                _rf(
                    "owasp2025.a10.python.broad-except",
                    "A10",
                    "Broad or bare except",
                    "Can hide failures and security-relevant errors.",
                    "low",
                    "heuristic",
                    rel_posix,
                    i,
                    line.strip()[:300],
                    fix_class="local_logic",
                    behavior_change=True,
                )
            )
    return out


def analyze_lines_js_tier1(rel_posix: str, lines: list[str]) -> list[RawFinding]:
    out: list[RawFinding] = []
    for i, line in enumerate(lines, start=1):
        if re.search(r"\.\s*innerHTML\s*=", line):
            out.append(
                _rf(
                    "owasp2025.a05.js.inner-html",
                    "A05",
                    "Assignment to innerHTML",
                    "Can lead to XSS when data is influenced.",
                    "high",
                    "heuristic",
                    rel_posix,
                    i,
                    line.strip()[:300],
                    fix_class="local_logic",
                    behavior_change=True,
                    cwe=[79],
                )
            )
        if "dangerouslySetInnerHTML" in line:
            out.append(
                _rf(
                    "owasp2025.a05.react.dangerous-inner",
                    "A05",
                    "dangerouslySetInnerHTML used",
                    "Raw HTML requires strict trust assumptions.",
                    "high",
                    "heuristic",
                    rel_posix,
                    i,
                    line.strip()[:300],
                    fix_class="local_logic",
                    behavior_change=True,
                    cwe=[79],
                )
            )
        if re.search(r"\beval\s*\(", line):
            out.append(
                _rf(
                    "owasp2025.a05.js.eval",
                    "A05",
                    "eval() used",
                    "Common injection primitive.",
                    "high",
                    "heuristic",
                    rel_posix,
                    i,
                    line.strip()[:300],
                    fix_class="sensitive",
                    behavior_change=True,
                    cwe=[94],
                )
            )
        if re.search(r"createHash\s*\(\s*['\"]md5['\"]", line) or re.search(
            r"createHash\s*\(\s*['\"]sha1['\"]", line
        ):
            out.append(
                _rf(
                    "owasp2025.a04.js.weak-hash",
                    "A04",
                    "Weak Node hash (MD5/SHA1)",
                    "Prefer SHA-256+ for integrity/security uses.",
                    "medium",
                    "heuristic",
                    rel_posix,
                    i,
                    line.strip()[:300],
                    fix_class="local_logic",
                    behavior_change=True,
                )
            )
        low = line.lower()
        if 'target="_blank"' in line or "target='_blank'" in line:
            if "noopener" not in low and "noreferrer" not in low:
                out.append(
                    _rf(
                        "owasp2025.a05.html.target-blank-no-opener",
                        "A05",
                        "target=_blank without rel=noopener",
                        "Tab-nabbing risk in some browsers.",
                        "low",
                        "rule",
                        rel_posix,
                        i,
                        line.strip()[:300],
                        fix_class="mechanical",
                        behavior_change=False,
                        patch_candidate=True,
                        cwe=[1021],
                    )
                )
    return out


def analyze_generic(rel_posix: str, lines: list[str]) -> list[RawFinding]:
    out: list[RawFinding] = []
    for i, line in enumerate(lines, start=1):
        if re.search(
            r"(password|secret|api[_-]?key)\s*=\s*[\"'][^\"'\n]{4,}[\"']",
            line,
            re.I,
        ):
            if "os.environ" in line or "process.env" in line:
                continue
            out.append(
                _rf(
                    "owasp2025.a07.possible-hardcoded-secret",
                    "A07",
                    "Possible hardcoded credential",
                    "Literals in source leak to anyone with repo access.",
                    "high",
                    "heuristic",
                    rel_posix,
                    i,
                    line.strip()[:120],
                    fix_class="sensitive",
                    behavior_change=True,
                    blast_radius="module",
                )
            )
            break
    return out


def check_package_lock_present(root: Path, rel_posix: str) -> list[RawFinding]:
    pj = root / rel_posix
    if pj.name.lower() != "package.json":
        return []
    d = pj.parent
    if any((d / n).is_file() for n in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml")):
        return []
    return [
        _rf(
            "owasp2025.a03.npm.no-lockfile",
            "A03",
            "No npm lockfile next to package.json",
            "Lockfiles improve reproducibility (no CVE correlation in v1).",
            "medium",
            "heuristic",
            rel_posix,
            1,
            "package.json",
            fix_class="mechanical",
            behavior_change=False,
            limitations=A03_LIMIT,
            blast_radius="module",
        )
    ]


def run_rules_on_file(root: Path, rel_posix: str, tier: str, text: str) -> list[RawFinding]:
    lines = text.splitlines()
    name = PurePosixPath(rel_posix).name.lower()
    suf = PurePosixPath(rel_posix).suffix.lower()
    out: list[RawFinding] = []

    if name == "dockerfile" or name.startswith("dockerfile."):
        out.extend(analyze_dockerfile(rel_posix, lines))
    if "docker-compose" in name and name.endswith((".yml", ".yaml")):
        out.extend(analyze_compose(rel_posix, text))
    if name == "package.json":
        out.extend(analyze_package_json(rel_posix, text))
        out.extend(check_package_lock_present(root, rel_posix))
    if name.startswith("requirements") and name.endswith(".txt"):
        out.extend(analyze_requirements(rel_posix, lines))

    if tier == "tier1" and suf == ".py":
        out.extend(analyze_lines_python_tier1(rel_posix, lines))
    elif tier == "tier1" and suf in (
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
        ".vue",
        ".svelte",
        ".html",
        ".htm",
    ):
        out.extend(analyze_lines_js_tier1(rel_posix, lines))
    elif tier == "best_effort":
        out.extend(analyze_generic(rel_posix, lines))

    if tier == "context" and suf in (".yml", ".yaml", ".tf"):
        out.extend(analyze_generic(rel_posix, lines))

    return out
