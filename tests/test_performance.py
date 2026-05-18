"""
Performance baseline tests.

These are NOT pass/fail tests - they print timings so we can detect
regressions over time. Run with:

    python -m pytest tests/test_performance.py -v -s

The numbers we publish in README/docs come from these tests.
"""
from __future__ import annotations

import time

import pytest

from pdf_defang import sanitize, sanitize_bytes


def _time(func, iterations: int = 100) -> dict[str, float]:
    """Run func() iterations times, return min/median/mean timing in ms."""
    times: list[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        func()
        times.append((time.perf_counter() - t0) * 1000)
    times.sort()
    return {
        "min_ms": times[0],
        "median_ms": times[len(times) // 2],
        "mean_ms": sum(times) / len(times),
        "max_ms": times[-1],
    }


@pytest.mark.benchmark
def test_scan_clean_pdf_timing(fixture_pdf, capsys):
    """Scanning a clean PDF should be near-instant."""
    pdf_bytes = fixture_pdf("clean.pdf").read_bytes()

    def run() -> None:
        # scan_bytes avoids file I/O so we measure pure parser time
        from pdf_defang import scan_bytes
        scan_bytes(pdf_bytes)

    results = _time(run, iterations=100)
    with capsys.disabled():
        print(f"\n  scan(clean.pdf): median={results['median_ms']:.2f}ms "
              f"min={results['min_ms']:.2f}ms max={results['max_ms']:.2f}ms")
    # Soft assertion: median should comfortably be under 10ms on a modern machine
    assert results["median_ms"] < 100, "Performance regression in scan path"


@pytest.mark.benchmark
def test_sanitize_clean_pdf_timing(tmp_path, fixture_pdf, capsys):
    """Sanitizing a clean PDF (no removals) - measures the base overhead."""
    import shutil
    src = fixture_pdf("clean.pdf")

    def run() -> None:
        dst = tmp_path / "perf_clean.pdf"
        shutil.copy(src, dst)
        sanitize(dst)

    results = _time(run, iterations=20)
    with capsys.disabled():
        print(f"\n  sanitize(clean.pdf): median={results['median_ms']:.2f}ms "
              f"min={results['min_ms']:.2f}ms max={results['max_ms']:.2f}ms")
    assert results["median_ms"] < 500


@pytest.mark.benchmark
def test_sanitize_kitchen_sink_timing(tmp_path, fixture_pdf, capsys):
    """Sanitizing a PDF with everything - worst case in our fixtures."""
    import shutil
    src = fixture_pdf("with_everything.pdf")

    def run() -> None:
        dst = tmp_path / "perf_everything.pdf"
        shutil.copy(src, dst)
        sanitize(dst)

    results = _time(run, iterations=20)
    with capsys.disabled():
        print(f"\n  sanitize(with_everything.pdf): median={results['median_ms']:.2f}ms "
              f"min={results['min_ms']:.2f}ms max={results['max_ms']:.2f}ms")
    assert results["median_ms"] < 500


@pytest.mark.benchmark
def test_sanitize_bytes_no_disk(fixture_pdf, capsys):
    """sanitize_bytes - no disk I/O at all, fastest path."""
    raw = fixture_pdf("with_js.pdf").read_bytes()

    def run() -> None:
        sanitize_bytes(raw)

    results = _time(run, iterations=50)
    with capsys.disabled():
        print(f"\n  sanitize_bytes(in-memory): median={results['median_ms']:.2f}ms "
              f"min={results['min_ms']:.2f}ms max={results['max_ms']:.2f}ms")
    assert results["median_ms"] < 200
