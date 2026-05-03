"""Write Markdown scan reports to disk (atomic UTF-8)."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

from owasp_top10_mcp.scan.markdown import render_markdown


def write_utf8_file_atomic(
    output_path: str, text: str, *, overwrite: bool
) -> tuple[str, int]:
    """Write UTF-8 text to ``output_path`` via temp file + ``os.replace``.

    ``output_path`` must already be absolute after ``expanduser()`` (relative paths
    rejected). Creates parent directories. If the target exists and ``overwrite`` is
    false, raises ``FileExistsError`` without modifying the file.
    """
    expanded = Path(output_path).expanduser()
    if not expanded.is_absolute():
        raise ValueError(
            "output_path must be an absolute path (after ~ expansion); "
            f"got {output_path!r}"
        )
    dest = expanded.resolve()
    dest_str = str(dest)
    if dest.exists() and not overwrite:
        raise FileExistsError(
            f"output_path exists and overwrite is false: {dest_str}"
        )
    dest.parent.mkdir(parents=True, exist_ok=True)
    payload = text.encode("utf-8")
    fd, tmp_name = tempfile.mkstemp(
        prefix=".owasp-report-",
        suffix=".tmp.md",
        dir=str(dest.parent),
    )
    try:
        with os.fdopen(fd, "wb") as tmp_f:
            tmp_f.write(payload)
        os.replace(tmp_name, dest)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return dest_str, len(payload)


def save_markdown_report(
    envelope: dict[str, Any], output_path: str, *, overwrite: bool = False
) -> dict[str, Any]:
    """Render ``envelope`` to Markdown, write to disk, return confirmation dict."""
    expanded = Path(output_path).expanduser()
    if not expanded.is_absolute():
        raise ValueError(
            "output_path must be an absolute path (after ~ expansion); "
            f"got {output_path!r}"
        )
    dest = expanded.resolve()
    if dest.exists() and not overwrite:
        raise FileExistsError(
            f"output_path exists and overwrite is false: {dest}"
        )
    body = render_markdown(envelope)
    path_str, nbytes = write_utf8_file_atomic(
        output_path, body, overwrite=overwrite
    )
    scan = envelope.get("scan", {})
    return {
        "path": path_str,
        "bytes_written": nbytes,
        "truncated": bool(scan.get("truncated")),
        "rulepack_version": scan.get("rulepack_version", ""),
        "product_version": scan.get("product_version", ""),
    }
