"""
Command-line interface for pdf-defang.

Two subcommands:

  pdf-defang clean <file> [...]      - sanitize one or more PDFs in place
  pdf-defang scan <file>             - inspect a PDF, report findings
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from ._core import SanitizeReport, sanitize
from ._scan import ScanReport, scan


def main(argv: list[str] | None = None) -> int:
    """Entry point for the ``pdf-defang`` console script."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "clean":
        return _cmd_clean(args)
    if args.command == "scan":
        return _cmd_scan(args)

    parser.print_help()
    return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pdf-defang",
        description="Strip JavaScript and active content from PDFs.",
    )
    parser.add_argument(
        "--version", action="version", version=f"pdf-defang {__version__}",
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    clean = sub.add_parser(
        "clean",
        help="Sanitize PDF(s) in place",
        description="Remove JavaScript, OpenAction, Launch actions and other "
                    "active content from one or more PDFs. Modifies files in place.",
    )
    clean.add_argument("files", nargs="+", help="PDF file(s) to sanitize")
    clean.add_argument(
        "--password", "-p", default=None,
        help="Password for encrypted PDF (applied to all files)",
    )
    clean.add_argument(
        "--level", "-l", choices=("strict", "balanced"), default="strict",
        help="Sanitization aggressiveness. 'strict' (default) strips all "
             "active content. 'balanced' keeps form interactivity and "
             "embedded files (PDF portfolios).",
    )
    clean.add_argument(
        "--json", "-j", action="store_true",
        help="Output detailed report as JSON instead of human-readable text",
    )
    clean.add_argument(
        "--quiet", "-q", action="store_true",
        help="Suppress per-file output; exit code still reflects outcome",
    )

    scan_p = sub.add_parser(
        "scan",
        help="Inspect a PDF without modifying it",
        description="Report what dangerous content a PDF contains, without "
                    "modifying the file. Use for forensics, upload validation, or audit.",
    )
    scan_p.add_argument("file", help="PDF file to inspect")
    scan_p.add_argument(
        "--password", "-p", default=None,
        help="Password for encrypted PDF",
    )
    scan_p.add_argument(
        "--json", "-j", action="store_true",
        help="Output report as JSON instead of human-readable text",
    )

    return parser


def _cmd_clean(args: argparse.Namespace) -> int:
    """
    Exit codes:
      0 = all files cleaned successfully
      1 = at least one file had something stripped (signal for callers)
      2 = at least one file failed (couldn't open, etc)
    """
    any_failed = False
    any_modified = False
    all_results: list[dict[str, object]] = []

    for file_path in args.files:
        if not Path(file_path).is_file():
            _emit(args, f"  {file_path}: not a file", error=True)
            any_failed = True
            continue

        report: SanitizeReport = sanitize(
            file_path, return_report=True, password=args.password, level=args.level,
        )

        if report.error:
            any_failed = True
            if not args.quiet:
                _emit(args, f"  {file_path}: ERROR - {report.error}", error=True)
            all_results.append({"file": file_path, **report.as_dict()})
            continue

        # Was anything actually removed?
        removed_anything = (
            report.javascript_in_names > 0
            or report.embedded_files > 0
            or report.open_action_removed
            or report.document_aa_removed
            or report.xfa_form_removed
            or report.calculation_order_removed
            or report.pages_with_aa > 0
            or report.annotations_with_actions > 0
            or report.annotations_with_js > 0
            or report.dangerous_uris_removed > 0
        )
        if removed_anything:
            any_modified = True

        if args.json:
            all_results.append({"file": file_path, **report.as_dict()})
        elif not args.quiet:
            if removed_anything:
                _emit(args, f"  {file_path}: cleaned ({_summarize_report(report)})")
            else:
                _emit(args, f"  {file_path}: already clean")

    if args.json:
        print(json.dumps(all_results, indent=2, ensure_ascii=False))

    if any_failed:
        return 2
    if any_modified:
        return 1
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    """
    Exit codes:
      0 = no dangerous content found
      1 = dangerous content found (risk_level != 'none')
      2 = could not scan (encrypted, malformed, etc)
    """
    report = scan(args.file, password=args.password)

    if args.json:
        print(json.dumps({"file": args.file, **report.as_dict()}, indent=2, ensure_ascii=False))
    else:
        _emit_scan_human(args.file, report)

    if report.error:
        return 2
    if report.risk_level == "none":
        return 0
    return 1


def _emit(args: argparse.Namespace, message: str, *, error: bool = False) -> None:
    stream = sys.stderr if error else sys.stdout
    print(message, file=stream)


def _emit_scan_human(file_path: str, report: ScanReport) -> None:
    print(f"PDF: {file_path}")
    if report.error:
        print(f"  ERROR: {report.error}")
        return
    print(f"  pages: {report.page_count}")
    print(f"  size: {report.file_size:,} bytes")
    print(f"  risk: {report.risk_level.upper()}")
    if report.has_javascript:
        print(f"  - document JavaScript: {report.javascript_in_names} entries")
    if report.has_open_action:
        print("  - /OpenAction set (auto-execute on open)")
    if report.has_document_aa:
        print("  - document /AA set (auto-execute on navigation)")
    if report.has_xfa_form:
        print("  - XFA form (legacy attack surface)")
    if report.has_embedded_files:
        print(f"  - embedded files: {report.embedded_files_count}")
    if report.pages_with_aa:
        print(f"  - pages with /AA: {report.pages_with_aa}")
    if report.annotations_with_actions:
        types = ", ".join(report.annotation_action_types) or "various"
        print(f"  - dangerous annotation actions: {report.annotations_with_actions} ({types})")
    if report.annotations_with_js:
        print(f"  - annotations with /JS: {report.annotations_with_js}")
    if report.dangerous_uris:
        schemes = ", ".join(f"{s}:" for s in report.dangerous_uri_schemes) or "unknown"
        print(f"  - dangerous URIs: {report.dangerous_uris} ({schemes})")
    if report.risk_level == "none":
        print("  no active content detected")


def _summarize_report(report: SanitizeReport) -> str:
    parts: list[str] = []
    if report.javascript_in_names:
        parts.append(f"{report.javascript_in_names} JS")
    if report.open_action_removed:
        parts.append("OpenAction")
    if report.document_aa_removed:
        parts.append("/AA")
    if report.xfa_form_removed:
        parts.append("XFA")
    if report.embedded_files:
        parts.append(f"{report.embedded_files} embedded")
    if report.pages_with_aa:
        parts.append(f"{report.pages_with_aa} page /AA")
    if report.annotations_with_actions:
        parts.append(f"{report.annotations_with_actions} annot actions")
    if report.annotations_with_js:
        parts.append(f"{report.annotations_with_js} annot JS")
    if report.dangerous_uris_removed:
        parts.append(f"{report.dangerous_uris_removed} dangerous URIs")
    return ", ".join(parts) if parts else "nothing"


if __name__ == "__main__":
    raise SystemExit(main())
