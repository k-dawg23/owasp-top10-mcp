"""MCP tool descriptions stay portable and distinguish scan vs report vs save."""

from __future__ import annotations

from owasp_top10_mcp.server import (
    owasp_report,
    owasp_report_save,
    owasp_scan,
    owasp_scan_save,
)


def test_tool_docstrings_portable_and_distinguish_outputs():
    assert owasp_scan.__doc__ and len(owasp_scan.__doc__) > 80
    assert owasp_report.__doc__ and len(owasp_report.__doc__) > 80
    assert owasp_report_save.__doc__ and len(owasp_report_save.__doc__) > 80
    assert owasp_scan_save.__doc__ and len(owasp_scan_save.__doc__) > 80
    for fn in (owasp_scan, owasp_report, owasp_report_save, owasp_scan_save):
        doc = fn.__doc__ or ""
        assert "Cursor" not in doc
    assert "JSON" in (owasp_scan.__doc__ or "")
    assert "Markdown" in (owasp_report.__doc__ or "")
    assert "Markdown" in (owasp_report_save.__doc__ or "")
    assert "JSON" in (owasp_scan_save.__doc__ or "")
