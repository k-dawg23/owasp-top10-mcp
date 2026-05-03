from __future__ import annotations

import os
from pathlib import Path

import pathspec


BLOCKED_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "dist",
        "build",
        "coverage",
        ".tox",
        ".terraform",
        "vendor",
        ".mypy_cache",
        ".pytest_cache",
        "target",
        ".next",
    }
)

TIER1_EXT = frozenset(
    {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".html", ".htm"}
)
BEST_EXT = frozenset(
    {
        ".tf",
        ".tfvars",
        ".yaml",
        ".yml",
        ".toml",
        ".json",
        ".go",
        ".rb",
        ".java",
        ".rs",
        ".php",
        ".cs",
    }
)
SPECIAL_NAMES = frozenset(
    {
        "dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        "package.json",
        "package-lock.json",
        "composer.json",
        "go.mod",
        "requirements.txt",
        "pipfile",
        "poetry.lock",
        "pnpm-lock.yaml",
        "yarn.lock",
        "chart.yaml",
        "kustomization.yaml",
        "kustomization.yml",
        "pyproject.toml",
    }
)


def load_gitignore_spec(root: Path) -> pathspec.PathSpec | None:
    gi = root / ".gitignore"
    if not gi.is_file():
        return None
    try:
        lines = gi.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    if not lines:
        return None
    return pathspec.PathSpec.from_lines("gitwildmatch", lines)


def _rel_posix(root: Path, full: Path) -> str:
    try:
        return full.relative_to(root.resolve()).as_posix()
    except ValueError:
        return full.as_posix()


def is_eligible_path(root: Path, rel: Path) -> tuple[bool, str]:
    """
    Returns (eligible, tier) where tier is tier1 | best_effort | context.
    """
    parts_lower = tuple(p.lower() for p in rel.parts)
    if any(p in BLOCKED_DIRS for p in rel.parts):
        return False, ""

    name_l = rel.name.lower()
    suf = rel.suffix.lower()

    # Docker / Compose
    if name_l == "dockerfile" or name_l.startswith("dockerfile."):
        return True, "context"
    if name_l.startswith("docker-compose") and suf in (".yml", ".yaml", ""):
        return True, "context"

    # CI
    if (
        len(rel.parts) >= 3
        and rel.parts[0] == ".github"
        and rel.parts[1] == "workflows"
        and suf in (".yml", ".yaml")
    ):
        return True, "context"

    # Lock / manifests
    if name_l in SPECIAL_NAMES or name_l in {"pipfile.lock"}:
        return True, "context"

    # IaC: Terraform anywhere
    if suf in (".tf", ".tfvars"):
        return True, "context"
    if len(rel.parts) >= 2 and rel.parts[0] in {"infra", "iac", "terraform"} and suf == ".tf":
        return True, "context"

    # Helm / Kustomize
    if name_l == "chart.yaml":
        return True, "context"
    if name_l.startswith("kustomization.") and suf in (".yml", ".yaml"):
        return True, "context"

    # K8s dir layouts
    if (
        len(parts_lower) >= 2
        and parts_lower[0] in {"k8s", "kubernetes", "deploy", "manifests"}
        and suf in (".yml", ".yaml")
    ):
        return True, "context"

    # Source tiers
    if suf in TIER1_EXT:
        return True, "tier1"
    if suf in BEST_EXT:
        # Limit .json noise
        if suf == ".json" and name_l not in {"package.json", "tsconfig.json"}:
            return False, ""
        return True, "best_effort"

    return False, ""


def should_ignore_gitignore(spec: pathspec.PathSpec | None, rel_posix: str) -> bool:
    if spec is None:
        return False
    return spec.match_file(rel_posix)


def iter_eligible_files(root: Path) -> list[tuple[Path, str, str]]:
    """
    Returns sorted list of (absolute_path, rel_posix, tier) for files to consider.
    """
    root = root.resolve()
    spec = load_gitignore_spec(root)
    out: list[tuple[Path, str, str]] = []
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in BLOCKED_DIRS]
        dpath = Path(dirpath)
        for fn in filenames:
            full = dpath / fn
            if not full.is_file():
                continue
            try:
                rel = full.relative_to(root)
            except ValueError:
                continue
            rel_posix = rel.as_posix()
            if should_ignore_gitignore(spec, rel_posix):
                continue
            ok, tier = is_eligible_path(root, rel)
            if not ok:
                continue
            out.append((full, rel_posix, tier))
    out.sort(key=lambda t: t[1])
    return out
