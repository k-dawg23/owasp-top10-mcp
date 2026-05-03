from __future__ import annotations

from pathlib import Path

import pytest

from owasp_top10_mcp.report_save import save_markdown_report
from owasp_top10_mcp.scan.engine import run_scan
from owasp_top10_mcp.scan.markdown import render_markdown
from owasp_top10_mcp.server import owasp_report_save

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "sample_repo"


def test_run_scan_basic():
    r = run_scan(str(FIXTURE), profile="human_full")
    assert r["schema_version"] == "1.0"
    assert r["scan"]["rulepack_version"] == "2025.1"
    assert r["scan"]["product_version"] == "1.0.2"
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


def test_markdown_cwe_mitre_link():
    r = run_scan(str(FIXTURE), profile="human_full")
    md = render_markdown(r)
    assert "https://cwe.mitre.org/data/definitions/79.html" in md
    assert "#### CWE" in md


def test_normalize_doc_url_category_slash():
    from owasp_top10_mcp.constants import normalize_doc_url, owasp_top10_url

    u = owasp_top10_url("A05")
    assert normalize_doc_url(u) == normalize_doc_url(u.rstrip("/"))


def _minimal_scan() -> dict:
    return {
        "rulepack_version": "2025.1",
        "product_version": "1.0.2",
        "profile": "human_full",
        "run_id": "r1",
        "time_ms": 1,
        "files_scanned": 0,
        "bytes_read": 0,
        "truncated": False,
        "truncation_reasons": [],
        "limits_applied": {},
    }


def _dummy_finding(**extra) -> dict:
    base = {
        "id": "a" * 64,
        "rule_id": "test.rule",
        "owasp": {"id": "A05", "year": 2025},
        "title": "Title",
        "description": "Desc",
        "severity": "high",
        "confidence": "heuristic",
        "location": {"path": "p.py", "start_line": 1, "end_line": 2},
        "evidence": {"snippet": ""},
        "references": [],
        "patch_candidate": False,
        "fix_class": "manual",
        "behavior_change": False,
        "blast_radius": "repo",
    }
    base.update(extra)
    return base


def test_further_reading_omitted_when_only_category_url():
    cat = "https://owasp.org/Top10/2025/A05_2025-Injection/"
    f = _dummy_finding(references=[cat])
    md = render_markdown(
        {"schema_version": "1.0", "scan": _minimal_scan(), "findings": [f]}
    )
    assert "#### Further reading" not in md


def test_further_reading_lists_supplementary_urls_only():
    cat = "https://owasp.org/Top10/2025/A05_2025-Injection/"
    extra = "https://example.com/security-guide"
    f = _dummy_finding(references=[cat, extra])
    md = render_markdown(
        {"schema_version": "1.0", "scan": _minimal_scan(), "findings": [f]}
    )
    assert "#### Further reading" in md
    assert extra in md
    fr_i = md.index("#### Further reading")
    # only one bullet in that section before description block
    chunk = md[fr_i : fr_i + 500]
    assert chunk.count("https://example.com") == 1
    assert "example.com/security-guide" in chunk


def test_further_reading_other_category_gets_owasp_label():
    a07 = "https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/"
    f = _dummy_finding(references=[a07])
    md = render_markdown(
        {"schema_version": "1.0", "scan": _minimal_scan(), "findings": [f]}
    )
    assert "#### Further reading" in md
    assert "OWASP Top 10:2025 - A07" in md


def test_write_report_bytes_match_render(tmp_path):
    r = run_scan(str(FIXTURE), profile="human_full")
    expected = render_markdown(r).encode("utf-8")
    out = tmp_path / "report.md"
    save_markdown_report(r, str(out), overwrite=False)
    assert out.read_bytes() == expected


def test_save_rejects_relative_output_path(tmp_path):
    r = run_scan(str(FIXTURE), profile="human_full")
    with pytest.raises(ValueError, match="absolute"):
        save_markdown_report(r, "relative/path/report.md", overwrite=False)


def test_save_refuses_overwrite_without_flag(tmp_path):
    r = run_scan(str(FIXTURE), profile="human_full")
    out = tmp_path / "report.md"
    out.write_bytes(b"original")
    with pytest.raises(FileExistsError):
        save_markdown_report(r, str(out), overwrite=False)
    assert out.read_bytes() == b"original"


def test_save_overwrite_replaces(tmp_path):
    r = run_scan(str(FIXTURE), profile="human_full")
    out = tmp_path / "report.md"
    out.write_bytes(b"old")
    save_markdown_report(r, str(out), overwrite=True)
    assert b"OWASP Top 10" in out.read_bytes()
    assert out.read_bytes() == render_markdown(r).encode("utf-8")


def test_save_markdown_report_result_keys(tmp_path):
    r = run_scan(str(FIXTURE), profile="human_full")
    out = tmp_path / "out.md"
    result = save_markdown_report(r, str(out), overwrite=False)
    assert result["path"] == str(out.resolve())
    assert result["bytes_written"] == len(render_markdown(r).encode("utf-8"))
    assert result["truncated"] == r["scan"]["truncated"]
    assert result["rulepack_version"] == "2025.1"
    assert result["product_version"] == "1.0.2"


def test_owasp_report_save_mcp_tool(tmp_path):
    out = tmp_path / "mcp.md"
    result = owasp_report_save(
        repo_root=str(FIXTURE),
        output_path=str(out),
        profile="human_full",
    )
    assert result["product_version"] == "1.0.2"
    assert result["bytes_written"] > 0
    assert result["path"] == str(out.resolve())
    assert "truncated" in result
    assert result["rulepack_version"] == "2025.1"
