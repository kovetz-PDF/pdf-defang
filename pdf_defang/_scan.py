"""
Read-only scan mode: inspect a PDF and report what dangerous content it
contains, without modifying the file. Useful for forensic analysis,
upload validation, and audit reporting.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Literal

import pikepdf

from ._core import _DANGEROUS_ACTION_TYPES, _count_named_tree_entries, _extract_scheme, _is_safe_uri

logger = logging.getLogger(__name__)

RiskLevel = Literal["none", "low", "medium", "high"]


@dataclass
class ScanReport:
    """
    Read-only inspection of a PDF's risk surface.
    """
    has_javascript: bool = False
    has_open_action: bool = False
    has_document_aa: bool = False
    has_xfa_form: bool = False
    has_embedded_files: bool = False
    javascript_in_names: int = 0
    embedded_files_count: int = 0
    pages_with_aa: int = 0
    annotations_with_actions: int = 0
    annotation_action_types: list[str] = field(default_factory=list)
    annotations_with_js: int = 0
    dangerous_uris: int = 0
    dangerous_uri_schemes: list[str] = field(default_factory=list)
    page_count: int = 0
    is_encrypted: bool = False
    risk_level: RiskLevel = "none"
    file_size: int = 0
    error: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "has_javascript": self.has_javascript,
            "has_open_action": self.has_open_action,
            "has_document_aa": self.has_document_aa,
            "has_xfa_form": self.has_xfa_form,
            "has_embedded_files": self.has_embedded_files,
            "javascript_in_names": self.javascript_in_names,
            "embedded_files_count": self.embedded_files_count,
            "pages_with_aa": self.pages_with_aa,
            "annotations_with_actions": self.annotations_with_actions,
            "annotation_action_types": list(self.annotation_action_types),
            "annotations_with_js": self.annotations_with_js,
            "dangerous_uris": self.dangerous_uris,
            "dangerous_uri_schemes": list(self.dangerous_uri_schemes),
            "page_count": self.page_count,
            "is_encrypted": self.is_encrypted,
            "risk_level": self.risk_level,
            "file_size": self.file_size,
            "error": self.error,
        }


def scan(
    pdf_path: str | os.PathLike[str],
    *,
    password: str | None = None,
) -> ScanReport:
    """
    Inspect ``pdf_path`` and return what dangerous content it contains.

    Does **not** modify the file. Use :func:`pdf_defang.sanitize` to
    actually strip the content.

    Args:
        pdf_path: Path to the PDF file to inspect.
        password: If the PDF is encrypted, supply the password.

    Returns:
        :class:`ScanReport` with detected findings and a ``risk_level``
        of ``"none"`` / ``"low"`` / ``"medium"`` / ``"high"``.
    """
    report = ScanReport()
    pdf_path_str = os.fspath(pdf_path)
    try:
        report.file_size = os.path.getsize(pdf_path_str)
    except OSError:
        pass

    try:
        with pikepdf.open(pdf_path_str, password=password or "") as pdf:
            report.page_count = len(pdf.pages)
            _scan_document_level(pdf, report)
            _scan_pages(pdf, report)
    except pikepdf.PasswordError:
        report.is_encrypted = True
        report.error = "encrypted: password required or wrong"
        return report
    except Exception as e:
        report.error = f"{type(e).__name__}: {e}"
        logger.warning("PDF scan failed for %s: %s", os.path.basename(pdf_path_str), e)
        return report

    report.risk_level = _calculate_risk(report)
    return report


def _scan_document_level(pdf: Any, report: ScanReport) -> None:
    root = pdf.Root

    if "/Names" in root:
        names = root.Names
        if "/JavaScript" in names:
            report.has_javascript = True
            report.javascript_in_names = _count_named_tree_entries(names.JavaScript)
        if "/EmbeddedFiles" in names:
            report.has_embedded_files = True
            report.embedded_files_count = _count_named_tree_entries(names.EmbeddedFiles)

    if "/OpenAction" in root:
        report.has_open_action = True

    if "/AA" in root:
        report.has_document_aa = True

    if "/AcroForm" in root:
        acro = root.AcroForm
        if "/XFA" in acro:
            report.has_xfa_form = True


def _scan_pages(pdf: Any, report: ScanReport) -> None:
    seen_types: set[str] = set()
    seen_uri_schemes: set[str] = set()
    for page in pdf.pages:
        if "/AA" in page:
            report.pages_with_aa += 1

        if "/Annots" not in page:
            continue
        try:
            annots = list(page.Annots)
        except Exception:
            continue

        for annot in annots:
            try:
                if "/A" in annot:
                    action = annot.A
                    stype = action.get("/S")
                    stype_str = str(stype) if stype is not None else ""
                    if stype_str in _DANGEROUS_ACTION_TYPES:
                        report.annotations_with_actions += 1
                        seen_types.add(stype_str.lstrip("/"))
                    elif stype_str == "/URI":
                        uri_value = action.get("/URI")
                        if uri_value is not None and not _is_safe_uri(str(uri_value)):
                            report.dangerous_uris += 1
                            scheme = _extract_scheme(str(uri_value))
                            if scheme:
                                seen_uri_schemes.add(scheme)
                if "/AA" in annot:
                    report.annotations_with_actions += 1
                if "/JS" in annot:
                    report.annotations_with_js += 1
            except Exception:
                continue
    report.annotation_action_types = sorted(seen_types)
    report.dangerous_uri_schemes = sorted(seen_uri_schemes)


def _calculate_risk(report: ScanReport) -> RiskLevel:
    """
    Bucket the findings into none/low/medium/high.

    Rules:
      - high:   any JS in /Names, any OpenAction, any document /AA, any XFA,
                any Launch/ImportData/GoToR annotation, any dangerous URI
                (javascript:, file:, data:, UNC path, etc.)
      - medium: any other annotation actions, any embedded files,
                any page-level /AA
      - low:    JS exists in annotations but no execution triggers
      - none:   nothing found
    """
    high_actions = {"Launch", "ImportData", "GoToR"}
    high_signals = (
        report.has_javascript
        or report.has_open_action
        or report.has_document_aa
        or report.has_xfa_form
        or report.dangerous_uris > 0
        or any(t in high_actions for t in report.annotation_action_types)
    )
    if high_signals:
        return "high"
    medium_signals = (
        report.annotations_with_actions > 0
        or report.has_embedded_files
        or report.pages_with_aa > 0
    )
    if medium_signals:
        return "medium"
    if report.annotations_with_js > 0:
        return "low"
    return "none"
