"""Tests for pdf_defang.scan()."""
from __future__ import annotations


import pikepdf

from pdf_defang import ScanReport, scan


class TestScanBasic:
    def test_returns_scan_report(self, fixture_pdf):
        pdf_path = fixture_pdf("clean.pdf")
        report = scan(pdf_path)
        assert isinstance(report, ScanReport)

    def test_clean_pdf_has_no_findings(self, fixture_pdf):
        pdf_path = fixture_pdf("clean.pdf")
        report = scan(pdf_path)
        assert not report.has_javascript
        assert not report.has_open_action
        assert not report.has_document_aa
        assert not report.has_xfa_form
        assert not report.has_embedded_files
        assert report.annotations_with_actions == 0
        assert report.risk_level == "none"
        assert report.error is None

    def test_returns_error_on_missing_file(self, tmp_path):
        report = scan(tmp_path / "missing.pdf")
        assert report.error is not None
        assert report.risk_level == "none"  # default when scan failed


class TestScanDetects:
    def test_detects_javascript(self, fixture_pdf):
        pdf_path = fixture_pdf("with_js.pdf")
        report = scan(pdf_path)
        assert report.has_javascript is True
        assert report.javascript_in_names >= 1
        assert report.risk_level == "high"

    def test_detects_open_action(self, fixture_pdf):
        pdf_path = fixture_pdf("with_openaction.pdf")
        report = scan(pdf_path)
        assert report.has_open_action is True
        assert report.risk_level == "high"

    def test_detects_embedded_files(self, fixture_pdf):
        pdf_path = fixture_pdf("with_embedded.pdf")
        report = scan(pdf_path)
        assert report.has_embedded_files is True
        assert report.embedded_files_count >= 1
        assert report.risk_level in ("medium", "high")  # embedded alone is medium

    def test_detects_launch_annotation(self, fixture_pdf):
        pdf_path = fixture_pdf("with_launch_annot.pdf")
        report = scan(pdf_path)
        assert report.annotations_with_actions >= 1
        assert "Launch" in report.annotation_action_types
        assert report.risk_level == "high"  # Launch is high-risk

    def test_detects_kitchen_sink(self, fixture_pdf):
        pdf_path = fixture_pdf("with_everything.pdf")
        report = scan(pdf_path)
        assert report.has_javascript
        assert report.has_open_action
        assert report.has_document_aa
        assert report.has_embedded_files
        assert report.pages_with_aa >= 1
        assert report.annotations_with_actions >= 1
        assert report.risk_level == "high"


class TestScanDoesNotModify:
    def test_scan_leaves_file_unchanged(self, fixture_pdf):
        pdf_path = fixture_pdf("with_everything.pdf")
        size_before = pdf_path.stat().st_size

        scan(pdf_path)

        size_after = pdf_path.stat().st_size
        assert size_before == size_after

        # The JavaScript is still there - scan didn't strip it
        with pikepdf.open(pdf_path) as pdf:
            assert "/OpenAction" in pdf.Root


class TestScanReportAsDict:
    def test_as_dict_is_json_serialisable(self, fixture_pdf):
        import json

        pdf_path = fixture_pdf("with_everything.pdf")
        report = scan(pdf_path)
        d = report.as_dict()
        # Should round-trip through JSON cleanly
        round_tripped = json.loads(json.dumps(d))
        assert round_tripped["risk_level"] == "high"
        assert round_tripped["has_javascript"] is True
