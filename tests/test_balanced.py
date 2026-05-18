"""
Tests for the ``level="balanced"`` sanitization mode.

``balanced`` is the form-friendly variant: pure attack vectors are still
stripped, but form interactivity (SubmitForm/ResetForm/form JS,
annotation /AA, annotation /JS, AcroForm /CO) and embedded files
(PDF portfolios) are preserved.
"""
from __future__ import annotations

import pytest
import pikepdf

from pdf_defang import sanitize, sanitize_bytes


def _read_bytes(path) -> bytes:
    with open(path, "rb") as f:
        return f.read()


class TestBalancedKeepsFormBehaviour:
    def test_balanced_keeps_submitform_resetform_and_form_js(self, fixture_pdf):
        pdf_path = fixture_pdf("with_form_actions.pdf")
        report = sanitize(pdf_path, return_report=True, level="balanced")
        assert report.error is None
        assert report.level == "balanced"

        # All three form action types must survive
        with pikepdf.open(pdf_path) as pdf:
            actions = []
            for page in pdf.pages:
                if "/Annots" not in page:
                    continue
                for annot in page.Annots:
                    if "/A" in annot:
                        stype = annot.A.get("/S")
                        if stype is not None:
                            actions.append(str(stype))
            assert "/SubmitForm" in actions
            assert "/ResetForm" in actions
            assert "/JavaScript" in actions

    def test_balanced_keeps_annotation_aa_and_js(self, fixture_pdf):
        pdf_path = fixture_pdf("with_form_actions.pdf")
        sanitize(pdf_path, level="balanced")

        with pikepdf.open(pdf_path) as pdf:
            found_aa = found_js = False
            for page in pdf.pages:
                if "/Annots" not in page:
                    continue
                for annot in page.Annots:
                    if "/AA" in annot:
                        found_aa = True
                    if "/JS" in annot:
                        found_js = True
            assert found_aa, "annotation /AA should be preserved in balanced"
            assert found_js, "annotation /JS should be preserved in balanced"

    def test_balanced_keeps_calculation_order(self, fixture_pdf):
        pdf_path = fixture_pdf("with_form_actions.pdf")
        report = sanitize(pdf_path, return_report=True, level="balanced")
        assert report.calculation_order_removed is False

        with pikepdf.open(pdf_path) as pdf:
            assert "/AcroForm" in pdf.Root
            assert "/CO" in pdf.Root.AcroForm

    def test_balanced_keeps_embedded_files(self, fixture_pdf):
        pdf_path = fixture_pdf("with_form_actions.pdf")
        report = sanitize(pdf_path, return_report=True, level="balanced")
        assert report.embedded_files == 0  # not removed → counter stays 0

        with pikepdf.open(pdf_path) as pdf:
            assert "/Names" in pdf.Root
            assert "/EmbeddedFiles" in pdf.Root.Names


class TestBalancedStillStripsAttacks:
    def test_balanced_removes_document_javascript(self, fixture_pdf):
        pdf_path = fixture_pdf("with_js.pdf")
        report = sanitize(pdf_path, return_report=True, level="balanced")
        assert report.javascript_in_names >= 1
        with pikepdf.open(pdf_path) as pdf:
            if "/Names" in pdf.Root:
                assert "/JavaScript" not in pdf.Root.Names

    def test_balanced_removes_open_action(self, fixture_pdf):
        pdf_path = fixture_pdf("with_openaction.pdf")
        report = sanitize(pdf_path, return_report=True, level="balanced")
        assert report.open_action_removed is True
        with pikepdf.open(pdf_path) as pdf:
            assert "/OpenAction" not in pdf.Root

    def test_balanced_removes_launch_annotation(self, fixture_pdf):
        pdf_path = fixture_pdf("with_launch_annot.pdf")
        report = sanitize(pdf_path, return_report=True, level="balanced")
        assert report.annotations_with_actions >= 1
        assert "Launch" in report.annotation_action_types
        with pikepdf.open(pdf_path) as pdf:
            for page in pdf.pages:
                if "/Annots" not in page:
                    continue
                for annot in page.Annots:
                    if "/A" in annot:
                        assert str(annot.A.get("/S")) != "/Launch"

    def test_balanced_removes_gotor(self, fixture_pdf):
        pdf_path = fixture_pdf("with_gotor.pdf")
        report = sanitize(pdf_path, return_report=True, level="balanced")
        assert "GoToR" in report.annotation_action_types

    def test_balanced_removes_dangerous_uris(self, fixture_pdf):
        pdf_path = fixture_pdf("with_dangerous_uris.pdf")
        report = sanitize(pdf_path, return_report=True, level="balanced")
        assert report.dangerous_uris_removed >= 3  # javascript:, file:, UNC
        # Safe https URL must survive
        with pikepdf.open(pdf_path) as pdf:
            uris_left = []
            for page in pdf.pages:
                if "/Annots" not in page:
                    continue
                for annot in page.Annots:
                    if "/A" in annot:
                        a = annot.A
                        if str(a.get("/S", "")) == "/URI":
                            uris_left.append(str(a.get("/URI", "")))
            assert any("example.com" in u for u in uris_left)


class TestStrictDefaultUnchanged:
    """Existing strict behaviour MUST be the default."""

    def test_default_level_is_strict(self, fixture_pdf):
        pdf_path = fixture_pdf("with_form_actions.pdf")
        report = sanitize(pdf_path, return_report=True)
        assert report.level == "strict"
        assert report.embedded_files >= 1
        assert report.calculation_order_removed is True
        assert report.annotations_with_actions >= 1  # SubmitForm/Reset/JS stripped
        assert report.annotations_with_js >= 1       # /JS key stripped

    def test_strict_removes_form_actions(self, fixture_pdf):
        pdf_path = fixture_pdf("with_form_actions.pdf")
        sanitize(pdf_path, level="strict")

        with pikepdf.open(pdf_path) as pdf:
            for page in pdf.pages:
                if "/Annots" not in page:
                    continue
                for annot in page.Annots:
                    if "/A" in annot:
                        stype = str(annot.A.get("/S", ""))
                        assert stype not in {"/SubmitForm", "/ResetForm", "/JavaScript"}
                    assert "/AA" not in annot
                    assert "/JS" not in annot

            # CO and EmbeddedFiles both removed
            if "/Names" in pdf.Root:
                assert "/EmbeddedFiles" not in pdf.Root.Names
            if "/AcroForm" in pdf.Root:
                assert "/CO" not in pdf.Root.AcroForm


class TestLevelValidation:
    def test_invalid_level_raises(self, fixture_pdf):
        pdf_path = fixture_pdf("clean.pdf")
        with pytest.raises(ValueError, match="strict.*balanced"):
            sanitize(pdf_path, level="aggressive")  # type: ignore[arg-type]

    def test_invalid_level_raises_in_bytes_api(self, fixture_pdf):
        data = _read_bytes(fixture_pdf("clean.pdf"))
        with pytest.raises(ValueError, match="strict.*balanced"):
            sanitize_bytes(data, level="paranoid")  # type: ignore[arg-type]


class TestBalancedBytesAPI:
    def test_bytes_balanced_keeps_form_actions(self, fixture_pdf):
        data = _read_bytes(fixture_pdf("with_form_actions.pdf"))
        cleaned, report = sanitize_bytes(data, return_report=True, level="balanced")
        assert report.error is None
        assert report.level == "balanced"
        assert report.embedded_files == 0  # not stripped
        assert report.calculation_order_removed is False

    def test_bytes_strict_still_strips_everything(self, fixture_pdf):
        data = _read_bytes(fixture_pdf("with_form_actions.pdf"))
        cleaned, report = sanitize_bytes(data, return_report=True, level="strict")
        assert report.level == "strict"
        assert report.embedded_files >= 1
        assert report.calculation_order_removed is True
        assert report.annotations_with_actions >= 1
