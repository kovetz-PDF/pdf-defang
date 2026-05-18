"""
Tests for the v0.1.0 expanded protection set:
- URI scheme filtering (javascript:, file:, data:, UNC paths)
- Extended dangerous action types (/GoToR, /GoToE, /Movie, /Sound)
"""
from __future__ import annotations

import pikepdf
import pytest

from pdf_defang import sanitize, scan
from pdf_defang._core import _extract_scheme, _is_safe_uri


class TestUriSchemeHelper:
    """Unit tests for the helper functions, no PDF needed."""

    @pytest.mark.parametrize("uri,expected_safe", [
        # Safe schemes
        ("http://example.com", True),
        ("https://example.com/path?q=1", True),
        ("mailto:user@example.com", True),
        ("tel:+1-555-1234", True),
        ("ftp://files.example.com/x.txt", True),
        # Relative URIs - safe
        ("", True),
        ("page2.pdf", True),
        ("#section1", True),
        ("/relative/path", True),
        # Dangerous schemes
        ("javascript:alert(1)", False),
        ("JAVASCRIPT:alert(1)", False),  # case-insensitive
        ("file:///etc/passwd", False),
        ("data:text/html,<script>alert(1)</script>", False),
        ("vbscript:msgbox(1)", False),
        # UNC paths (Windows)
        ("\\\\server\\share\\file.exe", False),
        ("//server/share/file.exe", False),
    ])
    def test_is_safe_uri(self, uri: str, expected_safe: bool):
        assert _is_safe_uri(uri) is expected_safe

    @pytest.mark.parametrize("uri,expected_scheme", [
        ("http://example.com", "http"),
        ("HTTPS://example.com", "https"),
        ("javascript:alert(1)", "javascript"),
        ("\\\\server\\share", "unc"),
        ("//server/share", "unc"),
        ("", ""),
        ("page.pdf", ""),
        ("not a real:: scheme", ""),  # invalid scheme chars
    ])
    def test_extract_scheme(self, uri: str, expected_scheme: str):
        assert _extract_scheme(uri) == expected_scheme


class TestDangerousUriDetection:
    """The scanner should flag dangerous URIs in annotations."""

    def test_scan_detects_javascript_uri(self, fixture_pdf):
        pdf_path = fixture_pdf("with_dangerous_uris.pdf")
        report = scan(pdf_path)
        assert report.dangerous_uris >= 1
        assert "javascript" in report.dangerous_uri_schemes
        assert report.risk_level == "high"

    def test_scan_detects_file_uri(self, fixture_pdf):
        pdf_path = fixture_pdf("with_dangerous_uris.pdf")
        report = scan(pdf_path)
        assert "file" in report.dangerous_uri_schemes

    def test_scan_detects_unc_path(self, fixture_pdf):
        pdf_path = fixture_pdf("with_dangerous_uris.pdf")
        report = scan(pdf_path)
        assert "unc" in report.dangerous_uri_schemes

    def test_scan_does_not_flag_safe_https_uri(self, fixture_pdf):
        """The fixture has 3 dangerous + 1 safe URL. We should detect exactly 3."""
        pdf_path = fixture_pdf("with_dangerous_uris.pdf")
        report = scan(pdf_path)
        assert report.dangerous_uris == 3  # NOT 4 - the https one is safe


class TestDangerousUriRemoval:
    """The sanitizer should strip dangerous URI actions and leave safe ones."""

    def test_sanitize_removes_dangerous_uris(self, fixture_pdf):
        pdf_path = fixture_pdf("with_dangerous_uris.pdf")
        report = sanitize(pdf_path, return_report=True)

        assert report.dangerous_uris_removed == 3
        # All three dangerous schemes should appear
        assert "javascript" in report.dangerous_uri_schemes_removed
        assert "file" in report.dangerous_uri_schemes_removed
        assert "unc" in report.dangerous_uri_schemes_removed

    def test_safe_https_url_preserved(self, fixture_pdf):
        """The https:// link should still be there after sanitization."""
        pdf_path = fixture_pdf("with_dangerous_uris.pdf")
        sanitize(pdf_path)

        # Re-open and count remaining URI actions
        remaining_uris: list[str] = []
        with pikepdf.open(pdf_path) as pdf:
            for page in pdf.pages:
                if "/Annots" not in page:
                    continue
                for annot in page.Annots:
                    if "/A" in annot:
                        action = annot.A
                        if str(action.get("/S", "")) == "/URI":
                            uri = action.get("/URI")
                            if uri:
                                remaining_uris.append(str(uri))
        # Only the safe https URL should remain
        assert len(remaining_uris) == 1
        assert remaining_uris[0].startswith("https://")


class TestNewDangerousActions:
    """Tests for /GoToR, /GoToE, /Movie, /Sound that we added in v0.1.0."""

    def test_scan_detects_gotor(self, fixture_pdf):
        pdf_path = fixture_pdf("with_gotor.pdf")
        report = scan(pdf_path)
        assert report.annotations_with_actions >= 1
        assert "GoToR" in report.annotation_action_types
        assert report.risk_level == "high"  # GoToR is high-risk

    def test_sanitize_removes_gotor(self, fixture_pdf):
        pdf_path = fixture_pdf("with_gotor.pdf")
        report = sanitize(pdf_path, return_report=True)
        assert report.annotations_with_actions >= 1
        assert "GoToR" in report.annotation_action_types

        # Verify it was actually removed
        with pikepdf.open(pdf_path) as pdf:
            for page in pdf.pages:
                if "/Annots" not in page:
                    continue
                for annot in page.Annots:
                    if "/A" in annot:
                        assert str(annot.A.get("/S", "")) != "/GoToR"

    def test_scan_detects_movie_sound(self, fixture_pdf):
        pdf_path = fixture_pdf("with_movie_sound.pdf")
        report = scan(pdf_path)
        assert report.annotations_with_actions >= 2
        assert "Movie" in report.annotation_action_types
        assert "Sound" in report.annotation_action_types

    def test_sanitize_removes_movie_sound(self, fixture_pdf):
        pdf_path = fixture_pdf("with_movie_sound.pdf")
        report = sanitize(pdf_path, return_report=True)
        assert "Movie" in report.annotation_action_types
        assert "Sound" in report.annotation_action_types


class TestRiskLevelWithNewProtections:
    def test_gotor_alone_is_high_risk(self, fixture_pdf):
        """GoToR is in the high-risk action set."""
        assert scan(fixture_pdf("with_gotor.pdf")).risk_level == "high"

    def test_dangerous_uri_alone_is_high_risk(self, fixture_pdf):
        """A javascript: URI alone is enough to bump risk to high."""
        assert scan(fixture_pdf("with_dangerous_uris.pdf")).risk_level == "high"

    def test_movie_sound_alone_is_medium(self, fixture_pdf):
        """Movie/Sound are dangerous actions but not in the high-priority list."""
        report = scan(fixture_pdf("with_movie_sound.pdf"))
        # 2 dangerous annotations, no /JS in /Names, no OpenAction = medium
        assert report.risk_level == "medium"


class TestReportFieldsRoundTrip:
    def test_sanitize_report_has_new_fields(self, fixture_pdf):
        report = sanitize(fixture_pdf("with_dangerous_uris.pdf"), return_report=True)
        d = report.as_dict()
        assert "dangerous_uris_removed" in d
        assert "dangerous_uri_schemes_removed" in d

    def test_scan_report_has_new_fields(self, fixture_pdf):
        report = scan(fixture_pdf("with_dangerous_uris.pdf"))
        d = report.as_dict()
        assert "dangerous_uris" in d
        assert "dangerous_uri_schemes" in d
