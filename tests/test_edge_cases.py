"""
Edge-case tests covering paths the main test files don't hit.

Bumps coverage of error branches, helper functions, and CLI edge cases.
"""
from __future__ import annotations

import json
from pathlib import Path

import pikepdf

from pdf_defang import sanitize, scan
from pdf_defang.cli import main


class TestPasswordProtected:
    """We don't fully support encrypted PDFs in v0.1, but the API must not
    blow up when one is encountered - it should return a clean error report."""

    def _make_encrypted(self, tmp_path: Path, password: str = "secret") -> Path:
        path = tmp_path / "encrypted.pdf"
        pdf = pikepdf.Pdf.new()
        pdf.add_blank_page(page_size=(612, 792))
        pdf.save(path, encryption=pikepdf.Encryption(owner=password, user=password, R=4))
        pdf.close()
        return path

    def test_sanitize_encrypted_without_password_reports_error(self, tmp_path):
        encrypted = self._make_encrypted(tmp_path)
        report = sanitize(encrypted, return_report=True)
        assert report.error is not None
        assert "encrypted" in report.error.lower()
        # File must NOT be modified
        assert encrypted.exists()

    def test_sanitize_encrypted_with_correct_password(self, tmp_path):
        encrypted = self._make_encrypted(tmp_path, password="hunter2")
        report = sanitize(encrypted, return_report=True, password="hunter2")
        assert report.error is None
        assert report.modified is True

    def test_scan_encrypted_without_password(self, tmp_path):
        encrypted = self._make_encrypted(tmp_path)
        report = scan(encrypted)
        assert report.is_encrypted is True
        assert report.error is not None


class TestSimpleBoolReturn:
    """When return_report=False (default), sanitize returns plain bool."""

    def test_returns_true_on_success(self, fixture_pdf):
        result = sanitize(fixture_pdf("with_js.pdf"))
        assert result is True

    def test_returns_false_on_invalid_pdf(self, tmp_path):
        # Not a PDF at all
        garbage = tmp_path / "not_a_pdf.pdf"
        garbage.write_bytes(b"this is plain text, not a PDF")
        assert sanitize(garbage) is False


class TestAsDictRoundTrip:
    def test_sanitize_report_as_dict_json_safe(self, fixture_pdf):
        report = sanitize(fixture_pdf("with_everything.pdf"), return_report=True)
        d = report.as_dict()
        # Must round-trip through JSON without loss
        assert json.loads(json.dumps(d)) == d


class TestCliQuietMode:
    def test_quiet_suppresses_per_file_output(self, fixture_pdf, capsys):
        pdf = fixture_pdf("with_js.pdf")
        exit_code = main(["clean", "--quiet", str(pdf)])
        assert exit_code == 1  # still signals modification via exit code
        out = capsys.readouterr().out
        assert "cleaned" not in out  # quiet


class TestCliMissingFiles:
    def test_clean_partial_failure(self, fixture_pdf, tmp_path, capsys):
        """When some files succeed and some don't, exit code should be 2 (failure)."""
        valid = fixture_pdf("clean.pdf")
        missing = tmp_path / "missing.pdf"
        exit_code = main(["clean", str(valid), str(missing)])
        assert exit_code == 2  # 2 wins over 0/1


class TestScanRiskLevels:
    """Verify the risk-bucketing logic across all severity levels."""

    def test_clean_pdf_is_none_risk(self, fixture_pdf):
        assert scan(fixture_pdf("clean.pdf")).risk_level == "none"

    def test_embedded_only_is_medium(self, fixture_pdf):
        # with_embedded.pdf has only embedded files, no JS/OpenAction
        report = scan(fixture_pdf("with_embedded.pdf"))
        assert report.risk_level == "medium"

    def test_javascript_is_high(self, fixture_pdf):
        assert scan(fixture_pdf("with_js.pdf")).risk_level == "high"


class TestSanitizeAcceptsPathObject:
    """The function should accept both str and pathlib.Path."""

    def test_pathlib_path(self, fixture_pdf):
        path_obj = fixture_pdf("with_js.pdf")
        assert isinstance(path_obj, Path)
        assert sanitize(path_obj) is True

    def test_str_path(self, fixture_pdf):
        path_str = str(fixture_pdf("with_js.pdf"))
        assert sanitize(path_str) is True
