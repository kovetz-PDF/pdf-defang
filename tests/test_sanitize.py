"""Tests for pdf_defang.sanitize()."""
from __future__ import annotations


import pikepdf

from pdf_defang import SanitizeReport, sanitize


class TestSanitizeBasic:
    def test_clean_pdf_returns_true_no_changes(self, fixture_pdf):
        pdf_path = fixture_pdf("clean.pdf")
        assert sanitize(pdf_path) is True

    def test_clean_pdf_with_report(self, fixture_pdf):
        pdf_path = fixture_pdf("clean.pdf")
        report = sanitize(pdf_path, return_report=True)
        assert isinstance(report, SanitizeReport)
        assert report.modified is True
        assert report.javascript_in_names == 0
        assert report.embedded_files == 0
        assert not report.open_action_removed
        assert not report.document_aa_removed
        assert report.annotations_with_actions == 0
        assert report.error is None

    def test_returns_false_on_missing_file(self, tmp_path):
        nonexistent = tmp_path / "no_such.pdf"
        assert sanitize(nonexistent) is False

    def test_returns_report_with_error_on_missing(self, tmp_path):
        nonexistent = tmp_path / "no_such.pdf"
        report = sanitize(nonexistent, return_report=True)
        assert isinstance(report, SanitizeReport)
        assert report.modified is False
        assert report.error is not None


class TestSanitizeRemovesContent:
    def test_removes_document_javascript(self, fixture_pdf):
        pdf_path = fixture_pdf("with_js.pdf")
        report = sanitize(pdf_path, return_report=True)
        assert report.javascript_in_names >= 1

        # Verify it's gone from the file
        with pikepdf.open(pdf_path) as pdf:
            if "/Names" in pdf.Root:
                assert "/JavaScript" not in pdf.Root.Names

    def test_removes_open_action(self, fixture_pdf):
        pdf_path = fixture_pdf("with_openaction.pdf")
        report = sanitize(pdf_path, return_report=True)
        assert report.open_action_removed is True

        with pikepdf.open(pdf_path) as pdf:
            assert "/OpenAction" not in pdf.Root

    def test_removes_embedded_files(self, fixture_pdf):
        pdf_path = fixture_pdf("with_embedded.pdf")
        report = sanitize(pdf_path, return_report=True)
        assert report.embedded_files >= 1

        with pikepdf.open(pdf_path) as pdf:
            if "/Names" in pdf.Root:
                assert "/EmbeddedFiles" not in pdf.Root.Names

    def test_removes_launch_annotation(self, fixture_pdf):
        pdf_path = fixture_pdf("with_launch_annot.pdf")
        report = sanitize(pdf_path, return_report=True)
        assert report.annotations_with_actions >= 1
        assert "Launch" in report.annotation_action_types

        with pikepdf.open(pdf_path) as pdf:
            for page in pdf.pages:
                if "/Annots" not in page:
                    continue
                for annot in page.Annots:
                    if "/A" in annot:
                        action = annot.A
                        stype = action.get("/S")
                        assert str(stype) != "/Launch"


class TestSanitizeKitchenSink:
    def test_removes_everything_at_once(self, fixture_pdf):
        pdf_path = fixture_pdf("with_everything.pdf")
        report = sanitize(pdf_path, return_report=True)

        assert report.javascript_in_names >= 1
        assert report.embedded_files >= 1
        assert report.open_action_removed
        assert report.document_aa_removed
        assert report.pages_with_aa >= 1
        assert report.annotations_with_actions >= 1
        assert report.error is None

        # Verify the cleaned file is still a valid, openable PDF
        with pikepdf.open(pdf_path) as pdf:
            assert len(pdf.pages) == 3  # original page count preserved
            assert "/OpenAction" not in pdf.Root
            assert "/AA" not in pdf.Root


class TestSanitizeIdempotent:
    def test_running_twice_is_safe(self, fixture_pdf):
        """Sanitizing an already-clean file shouldn't break anything."""
        pdf_path = fixture_pdf("with_js.pdf")
        sanitize(pdf_path)
        # Second run on the now-clean file
        report = sanitize(pdf_path, return_report=True)
        assert report.modified is True  # we opened and re-saved
        assert report.javascript_in_names == 0
        assert report.error is None


class TestSanitizePreservesVisibleContent:
    def test_page_count_preserved(self, fixture_pdf):
        """Sanitization must NEVER change the visible content of a PDF."""
        for name in ["with_js.pdf", "with_openaction.pdf", "with_embedded.pdf",
                     "with_launch_annot.pdf", "with_everything.pdf"]:
            pdf_path = fixture_pdf(name)
            with pikepdf.open(pdf_path) as pdf:
                page_count_before = len(pdf.pages)

            sanitize(pdf_path)

            with pikepdf.open(pdf_path) as pdf:
                assert len(pdf.pages) == page_count_before, (
                    f"Page count changed for {name}!"
                )
