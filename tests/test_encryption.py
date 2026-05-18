"""
Full encrypted-PDF support tests.

Verifies that:
1. sanitize() with correct password strips dangerous content AND preserves encryption
2. sanitize() with wrong password fails cleanly with informative error
3. scan() with correct password reports correctly
4. scan() without password reports is_encrypted=True
"""
from __future__ import annotations

import pikepdf
import pytest

from pdf_defang import sanitize, scan


FIXTURE_PASSWORD = "secret123"


class TestEncryptedSanitize:
    def test_sanitize_encrypted_with_correct_password(self, fixture_pdf):
        """Encrypted PDF + correct password = sanitization works."""
        pdf_path = fixture_pdf("encrypted_with_js.pdf")
        report = sanitize(pdf_path, return_report=True, password=FIXTURE_PASSWORD)

        assert report.error is None
        assert report.modified is True
        # The dangerous content INSIDE the encrypted file was found and stripped
        assert report.javascript_in_names >= 1
        assert report.open_action_removed is True

    def test_sanitize_preserves_encryption(self, fixture_pdf):
        """After sanitization, the PDF must STILL be encrypted - not silently decrypted."""
        pdf_path = fixture_pdf("encrypted_with_js.pdf")
        sanitize(pdf_path, password=FIXTURE_PASSWORD)

        # Trying to open without password should still fail
        with pytest.raises(pikepdf.PasswordError):
            pikepdf.open(pdf_path)

        # Opening with the password should work
        with pikepdf.open(pdf_path, password=FIXTURE_PASSWORD) as pdf:
            # And the dangerous content should be gone
            if "/Names" in pdf.Root:
                assert "/JavaScript" not in pdf.Root.Names
            assert "/OpenAction" not in pdf.Root

    def test_sanitize_encrypted_wrong_password(self, fixture_pdf):
        """Wrong password = clean error, no file modification."""
        pdf_path = fixture_pdf("encrypted_with_js.pdf")
        original_bytes = pdf_path.read_bytes()

        report = sanitize(pdf_path, return_report=True, password="wrong_password")

        assert report.error is not None
        assert "encrypted" in report.error.lower() or "password" in report.error.lower()
        assert report.modified is False
        # The file MUST be untouched on failure
        assert pdf_path.read_bytes() == original_bytes

    def test_sanitize_encrypted_no_password(self, fixture_pdf):
        """No password at all = also reports as encrypted error, doesn't crash."""
        pdf_path = fixture_pdf("encrypted_with_js.pdf")
        original_bytes = pdf_path.read_bytes()

        report = sanitize(pdf_path, return_report=True)  # password=None

        assert report.error is not None
        # File must not be modified
        assert pdf_path.read_bytes() == original_bytes


class TestEncryptedScan:
    def test_scan_encrypted_with_correct_password(self, fixture_pdf):
        """Scan with password reveals contents."""
        pdf_path = fixture_pdf("encrypted_with_js.pdf")
        report = scan(pdf_path, password=FIXTURE_PASSWORD)

        assert report.error is None
        assert report.is_encrypted is False  # we successfully opened it
        assert report.has_javascript is True
        assert report.risk_level == "high"

    def test_scan_encrypted_no_password(self, fixture_pdf):
        """Scan without password reports it's encrypted (informational)."""
        pdf_path = fixture_pdf("encrypted_with_js.pdf")
        report = scan(pdf_path)

        assert report.is_encrypted is True
        assert report.error is not None

    def test_scan_does_not_modify_encrypted_file(self, fixture_pdf):
        pdf_path = fixture_pdf("encrypted_with_js.pdf")
        original_bytes = pdf_path.read_bytes()
        scan(pdf_path, password=FIXTURE_PASSWORD)
        assert pdf_path.read_bytes() == original_bytes


class TestEncryptionRoundTrip:
    """
    End-to-end: encrypt a file ourselves, sanitize it, verify it stays encrypted
    AND that the sanitization actually worked.
    """

    def test_full_round_trip(self, tmp_path):
        # 1. Build a fresh encrypted PDF with malicious content
        pdf = pikepdf.Pdf.new()
        pdf.add_blank_page(page_size=(612, 792))
        pdf.Root.OpenAction = pikepdf.Dictionary(
            S=pikepdf.Name("/JavaScript"),
            JS=pikepdf.String("alert('hi')"),
        )
        encrypted_path = tmp_path / "test_encrypted.pdf"
        pwd = "test_password_123"
        pdf.save(encrypted_path, encryption=pikepdf.Encryption(owner=pwd, user=pwd, R=4))
        pdf.close()

        # 2. Sanitize it
        report = sanitize(encrypted_path, return_report=True, password=pwd)
        assert report.error is None
        assert report.open_action_removed is True

        # 3. Verify still encrypted
        with pytest.raises(pikepdf.PasswordError):
            pikepdf.open(encrypted_path)

        # 4. Verify content stripped (with password)
        with pikepdf.open(encrypted_path, password=pwd) as pdf2:
            assert "/OpenAction" not in pdf2.Root
