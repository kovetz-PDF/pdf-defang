"""Tests for the bytes-in/bytes-out API."""
from __future__ import annotations

import pikepdf

from pdf_defang import SanitizeReport, ScanReport, sanitize_bytes, scan_bytes


class TestSanitizeBytes:
    def test_returns_bytes(self, fixture_pdf):
        path = fixture_pdf("with_js.pdf")
        raw = path.read_bytes()
        result = sanitize_bytes(raw)
        assert isinstance(result, bytes)
        assert result.startswith(b"%PDF")

    def test_does_not_modify_input(self, fixture_pdf):
        """Verify the input bytes object is not mutated."""
        path = fixture_pdf("with_js.pdf")
        raw = path.read_bytes()
        original_raw = bytes(raw)  # immutable copy

        sanitize_bytes(raw)
        assert raw == original_raw

    def test_does_not_touch_disk(self, fixture_pdf):
        """Sanitize_bytes should NOT modify the source file."""
        path = fixture_pdf("with_js.pdf")
        raw = path.read_bytes()
        original_file_bytes = path.read_bytes()

        sanitize_bytes(raw)

        # Source file unchanged
        assert path.read_bytes() == original_file_bytes

    def test_removes_js_from_bytes(self, fixture_pdf):
        path = fixture_pdf("with_js.pdf")
        raw = path.read_bytes()
        cleaned, report = sanitize_bytes(raw, return_report=True)

        assert report.javascript_in_names >= 1

        # Open the cleaned bytes and verify JS is gone
        import io
        with pikepdf.open(io.BytesIO(cleaned)) as pdf:
            if "/Names" in pdf.Root:
                assert "/JavaScript" not in pdf.Root.Names

    def test_invalid_pdf_returns_input_unchanged(self):
        garbage = b"not a pdf"
        cleaned, report = sanitize_bytes(garbage, return_report=True)
        assert cleaned == garbage
        assert report.error is not None

    def test_returns_report_tuple_when_requested(self, fixture_pdf):
        path = fixture_pdf("with_everything.pdf")
        raw = path.read_bytes()
        result = sanitize_bytes(raw, return_report=True)

        assert isinstance(result, tuple)
        assert len(result) == 2
        cleaned, report = result
        assert isinstance(cleaned, bytes)
        assert isinstance(report, SanitizeReport)
        assert report.javascript_in_names >= 1

    def test_encrypted_with_password(self, fixture_pdf):
        path = fixture_pdf("encrypted_with_js.pdf")
        raw = path.read_bytes()
        cleaned, report = sanitize_bytes(
            raw, return_report=True, password="secret123",
        )
        assert report.error is None
        assert report.javascript_in_names >= 1

    def test_encrypted_wrong_password(self, fixture_pdf):
        path = fixture_pdf("encrypted_with_js.pdf")
        raw = path.read_bytes()
        cleaned, report = sanitize_bytes(
            raw, return_report=True, password="wrong",
        )
        assert report.error is not None
        # Should return original input unchanged on error
        assert cleaned == raw


class TestScanBytes:
    def test_returns_report(self, fixture_pdf):
        raw = fixture_pdf("clean.pdf").read_bytes()
        report = scan_bytes(raw)
        assert isinstance(report, ScanReport)
        assert report.risk_level == "none"

    def test_detects_high_risk(self, fixture_pdf):
        raw = fixture_pdf("with_everything.pdf").read_bytes()
        report = scan_bytes(raw)
        assert report.risk_level == "high"
        assert report.has_javascript

    def test_encrypted_no_password(self, fixture_pdf):
        raw = fixture_pdf("encrypted_with_js.pdf").read_bytes()
        report = scan_bytes(raw)
        assert report.is_encrypted is True

    def test_encrypted_with_password(self, fixture_pdf):
        raw = fixture_pdf("encrypted_with_js.pdf").read_bytes()
        report = scan_bytes(raw, password="secret123")
        assert report.is_encrypted is False
        assert report.has_javascript

    def test_invalid_pdf_returns_error(self):
        report = scan_bytes(b"not a pdf")
        assert report.error is not None
