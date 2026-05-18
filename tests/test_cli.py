"""Tests for the pdf-defang CLI."""
from __future__ import annotations

import json

import pytest

from pdf_defang.cli import main


class TestCliClean:
    def test_clean_on_already_clean_file_returns_0(self, fixture_pdf, capsys):
        pdf_path = fixture_pdf("clean.pdf")
        exit_code = main(["clean", str(pdf_path)])
        assert exit_code == 0
        out = capsys.readouterr().out
        assert "already clean" in out

    def test_clean_on_malicious_file_returns_1(self, fixture_pdf, capsys):
        pdf_path = fixture_pdf("with_js.pdf")
        exit_code = main(["clean", str(pdf_path)])
        assert exit_code == 1  # 1 = something was modified
        out = capsys.readouterr().out
        assert "cleaned" in out

    def test_clean_on_missing_file_returns_2(self, tmp_path, capsys):
        nonexistent = tmp_path / "nope.pdf"
        exit_code = main(["clean", str(nonexistent)])
        assert exit_code == 2

    def test_clean_with_json_output(self, fixture_pdf, capsys):
        pdf_path = fixture_pdf("with_everything.pdf")
        exit_code = main(["clean", "--json", str(pdf_path)])
        assert exit_code == 1

        out = capsys.readouterr().out
        data = json.loads(out)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["file"] == str(pdf_path)
        assert data[0]["modified"] is True

    def test_clean_multiple_files(self, fixture_pdf, capsys):
        clean = fixture_pdf("clean.pdf")
        js = fixture_pdf("with_js.pdf")
        exit_code = main(["clean", str(clean), str(js)])
        # 1 = at least one file was modified
        assert exit_code == 1

    def test_clean_level_balanced_preserves_form_actions(self, fixture_pdf, capsys):
        pdf_path = fixture_pdf("with_form_actions.pdf")
        exit_code = main(["clean", "--level", "balanced", "--json", str(pdf_path)])
        assert exit_code in (0, 1)
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data[0]["level"] == "balanced"
        # SubmitForm / ResetForm / form JS / CO / embedded files all kept
        assert data[0]["embedded_files"] == 0
        assert data[0]["calculation_order_removed"] is False

    def test_clean_level_strict_is_default(self, fixture_pdf, capsys):
        pdf_path = fixture_pdf("with_form_actions.pdf")
        exit_code = main(["clean", "--json", str(pdf_path)])
        assert exit_code == 1
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data[0]["level"] == "strict"
        assert data[0]["embedded_files"] >= 1
        assert data[0]["calculation_order_removed"] is True

    def test_clean_invalid_level_rejected_by_argparse(self, fixture_pdf, capsys):
        pdf_path = fixture_pdf("clean.pdf")
        with pytest.raises(SystemExit):
            main(["clean", "--level", "paranoid", str(pdf_path)])


class TestCliScan:
    def test_scan_clean_file_returns_0(self, fixture_pdf, capsys):
        pdf_path = fixture_pdf("clean.pdf")
        exit_code = main(["scan", str(pdf_path)])
        assert exit_code == 0
        out = capsys.readouterr().out
        assert "no active content" in out.lower() or "risk: NONE" in out

    def test_scan_malicious_file_returns_1(self, fixture_pdf, capsys):
        pdf_path = fixture_pdf("with_everything.pdf")
        exit_code = main(["scan", str(pdf_path)])
        assert exit_code == 1
        out = capsys.readouterr().out
        assert "risk: HIGH" in out

    def test_scan_missing_file_returns_2(self, tmp_path, capsys):
        nonexistent = tmp_path / "nope.pdf"
        exit_code = main(["scan", str(nonexistent)])
        assert exit_code == 2

    def test_scan_json_output(self, fixture_pdf, capsys):
        pdf_path = fixture_pdf("with_js.pdf")
        exit_code = main(["scan", "--json", str(pdf_path)])
        assert exit_code == 1

        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["file"] == str(pdf_path)
        assert data["has_javascript"] is True
        assert data["risk_level"] == "high"


class TestCliMisc:
    def test_no_command_prints_help(self, capsys):
        exit_code = main([])
        assert exit_code == 2  # argparse convention for missing command

    def test_version(self, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["--version"])
        assert exc.value.code == 0
