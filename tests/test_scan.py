from __future__ import annotations

from pathlib import Path

import pytest

from owasp_top10_mcp.scan.engine import run_scan
from owasp_top10_mcp.scan.markdown import render_markdown

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "sample_repo"


def test_run_scan_basic():
    r = run_scan(str(FIXTURE), profile="human_full")
    assert r["schema_version"] == "1.0"
    assert r["scan"]["rulepack_version"] == "2025.1"
    assert r["scan"]["product_version"] == "1.0.0"
    ids = {f["owasp"]["id"] for f in r["findings"]}
    assert "A05" in ids or "A08" in ids or "A02" in ids


def test_category_filter():
    r = run_scan(str(FIXTURE), categories=["A02"], profile="human_full")
    for f in r["findings"]:
        assert f["owasp"]["id"] == "A02"


def test_severity_floor_agent_quick_drops_low():
    r = run_scan(str(FIXTURE), profile="agent_quick")
    for f in r["findings"]:
        assert f["severity"] in ("critical", "high", "medium")


def test_truncation_max_files():
    root = Path(__file__).resolve().parent / "fixtures" / "trunc_repo"
    root.mkdir(parents=True, exist_ok=True)
    try:
        for i in range(10):
            (root / f"f{i}.py").write_text("# x\n", encoding="utf-8")
        r = run_scan(str(root), profile="human_full", max_files=3)
        assert r["scan"]["files_scanned"] <= 3
        assert r["scan"]["truncated"] is True
        assert "max_files" in r["scan"]["truncation_reasons"]
    finally:
        import shutil

        shutil.rmtree(root, ignore_errors=True)


def test_markdown_contains_rulepack():
    r = run_scan(str(FIXTURE), profile="human_full")
    md = render_markdown(r)
    assert "2025.1" in md
    assert "owasp.org/Top10/2025" in md


def test_finding_id_stable():
    r1 = run_scan(str(FIXTURE), profile="human_full")
    r2 = run_scan(str(FIXTURE), profile="human_full")
    a = {f["id"] for f in r1["findings"]}
    b = {f["id"] for f in r2["findings"]}
    assert a == b


def test_invalid_repo():
    with pytest.raises(ValueError, match="repo_root"):
        run_scan("/nonexistent/path/that/does/not/exist")


def test_invalid_category():
    with pytest.raises(ValueError, match="Invalid OWASP"):
        run_scan(str(FIXTURE), categories=["A99"])


def test_patch_candidate_invariant():
    r = run_scan(str(FIXTURE), profile="human_full")
    for f in r["findings"]:
        if f.get("patch_candidate"):
            assert f["fix_class"] == "mechanical"
            assert f["behavior_change"] is False
        if f.get("fix_class") == "sensitive":
            assert f["patch_candidate"] is False
