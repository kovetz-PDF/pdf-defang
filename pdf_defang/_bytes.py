"""
Bytes-in / bytes-out API for in-memory PDF processing.

Useful when:
- You receive a PDF from an upload stream and want to process it before
  ever touching disk
- You're reading PDFs from S3, Redis, or another byte-source
- You want to integrate with FastAPI/Flask file handlers without temp files

Example::

    from pdf_defang import sanitize_bytes, scan_bytes

    # From an upload
    raw = await uploaded_file.read()
    clean = sanitize_bytes(raw)
    # 'clean' is now a sanitized PDF as bytes - serve back to user

    # Inspect first
    report = scan_bytes(raw)
    if report.risk_level == "high":
        clean = sanitize_bytes(raw)
"""
from __future__ import annotations

import io
import logging
from typing import Literal, overload

import pikepdf

from ._core import (
    Level,
    SanitizeReport,
    _preserve_encryption,
    _strip_document_level,
    _strip_pages,
    _validate_level,
)
from ._scan import ScanReport, _calculate_risk, _scan_document_level, _scan_pages

logger = logging.getLogger(__name__)


@overload
def sanitize_bytes(
    data: bytes,
    *,
    return_report: Literal[False] = False,
    password: str | None = None,
    level: Level = "strict",
) -> bytes: ...


@overload
def sanitize_bytes(
    data: bytes,
    *,
    return_report: Literal[True],
    password: str | None = None,
    level: Level = "strict",
) -> tuple[bytes, SanitizeReport]: ...


def sanitize_bytes(
    data: bytes,
    *,
    return_report: bool = False,
    password: str | None = None,
    level: Level = "strict",
) -> bytes | tuple[bytes, SanitizeReport]:
    """
    Sanitize a PDF given as bytes; return the cleaned bytes.

    Args:
        data: The PDF file content as bytes.
        return_report: If True, return ``(cleaned_bytes, SanitizeReport)``.
            If False, return just the cleaned bytes.
        password: For encrypted PDFs.
        level: ``"strict"`` (default) or ``"balanced"``. See
            :func:`pdf_defang.sanitize` for the full semantics.

    Returns:
        ``bytes`` if ``return_report`` is False - the sanitized PDF bytes.
        On failure, returns the original ``data`` unchanged.

        ``(bytes, SanitizeReport)`` if ``return_report`` is True. The
        ``SanitizeReport.error`` field describes any failure; on failure
        the returned bytes are the original input.

    Raises:
        ValueError: If ``level`` is not ``"strict"`` or ``"balanced"``.

    Note:
        Unlike :func:`pdf_defang.sanitize`, this does NOT modify any file
        on disk. Input bytes are read-only, output bytes are a fresh
        in-memory buffer.
    """
    _validate_level(level)
    report = SanitizeReport(level=level)
    report.file_size_before = len(data)

    try:
        with pikepdf.open(io.BytesIO(data), password=password or "") as pdf:
            encryption = _preserve_encryption(pdf, password)
            _strip_document_level(pdf, report, level)
            _strip_pages(pdf, report, level)
            out = io.BytesIO()
            if encryption is not None:
                pdf.save(out, encryption=encryption)
            else:
                pdf.save(out)
            cleaned = out.getvalue()
        report.modified = True
        report.file_size_after = len(cleaned)
    except pikepdf.PasswordError:
        report.error = "encrypted: password required or wrong"
        logger.warning("PDF sanitize_bytes needs password")
        return (data, report) if return_report else data
    except Exception as e:
        report.error = f"{type(e).__name__}: {e}"
        logger.warning("PDF sanitize_bytes failed: %s", e)
        return (data, report) if return_report else data

    return (cleaned, report) if return_report else cleaned


def scan_bytes(data: bytes, *, password: str | None = None) -> ScanReport:
    """
    Inspect a PDF given as bytes; return findings without modification.

    Args:
        data: The PDF file content as bytes.
        password: For encrypted PDFs.

    Returns:
        :class:`ScanReport` with detected findings and risk level.
    """
    report = ScanReport()
    report.file_size = len(data)

    try:
        with pikepdf.open(io.BytesIO(data), password=password or "") as pdf:
            report.page_count = len(pdf.pages)
            _scan_document_level(pdf, report)
            _scan_pages(pdf, report)
    except pikepdf.PasswordError:
        report.is_encrypted = True
        report.error = "encrypted: password required or wrong"
        return report
    except Exception as e:
        report.error = f"{type(e).__name__}: {e}"
        logger.warning("PDF scan_bytes failed: %s", e)
        return report

    report.risk_level = _calculate_risk(report)
    return report
