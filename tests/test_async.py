"""Tests for the async API."""
from __future__ import annotations

import asyncio

import pytest

from pdf_defang import SanitizeReport, ScanReport, sanitize_async, scan_async


@pytest.mark.asyncio
async def test_sanitize_async_clean_pdf(fixture_pdf):
    pdf_path = fixture_pdf("clean.pdf")
    result = await sanitize_async(pdf_path)
    assert result is True


@pytest.mark.asyncio
async def test_sanitize_async_with_report(fixture_pdf):
    pdf_path = fixture_pdf("with_js.pdf")
    report = await sanitize_async(pdf_path, return_report=True)
    assert isinstance(report, SanitizeReport)
    assert report.javascript_in_names >= 1


@pytest.mark.asyncio
async def test_sanitize_async_missing_file(tmp_path):
    result = await sanitize_async(tmp_path / "missing.pdf")
    assert result is False


@pytest.mark.asyncio
async def test_scan_async(fixture_pdf):
    pdf_path = fixture_pdf("with_everything.pdf")
    report = await scan_async(pdf_path)
    assert isinstance(report, ScanReport)
    assert report.risk_level == "high"


@pytest.mark.asyncio
async def test_async_runs_concurrently(tmp_path, fixture_pdf):
    """Run multiple sanitizations in parallel to prove non-blocking."""
    import shutil
    src = fixture_pdf("with_js.pdf")
    # Each concurrent task needs its own file - pikepdf's
    # allow_overwriting_input uses a temp file + rename, which races on
    # Windows if two tasks target the same path.
    paths = []
    for i in range(5):
        dst = tmp_path / f"concurrent_{i}.pdf"
        shutil.copy(src, dst)
        paths.append(dst)

    results = await asyncio.gather(
        *[sanitize_async(p) for p in paths]
    )
    assert all(r is True for r in results)


@pytest.mark.asyncio
async def test_async_with_encrypted_pdf(fixture_pdf):
    """Encrypted PDF support works through async path too."""
    pdf_path = fixture_pdf("encrypted_with_js.pdf")
    report = await sanitize_async(
        pdf_path, return_report=True, password="secret123",
    )
    assert report.error is None
    assert report.javascript_in_names >= 1
