"""
Batch-process a directory of PDFs.

Walks the directory recursively, sanitizes every PDF found (in place),
and writes a JSONL audit log with what was removed from each file.

Usage:
    python examples/batch_processor.py /path/to/pdf_directory
    python examples/batch_processor.py /path/to/pdfs --log audit.jsonl
    python examples/batch_processor.py /path/to/pdfs --dry-run  # scan only
    python examples/batch_processor.py /path/to/pdfs --level balanced
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from pdf_defang import sanitize, scan

logger = logging.getLogger("batch_processor")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="Directory to scan recursively")
    parser.add_argument(
        "--log", type=Path, default=Path("audit.jsonl"),
        help="JSONL audit log path (default: audit.jsonl)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Scan only - report findings without modifying files",
    )
    parser.add_argument(
        "--level", "-l", choices=("strict", "balanced"), default="strict",
        help="Sanitization level. 'strict' (default) removes all active "
             "content; 'balanced' preserves form interactivity and "
             "embedded files for trusted sources.",
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true",
        help="Suppress per-file progress output",
    )
    args = parser.parse_args()

    if not args.directory.is_dir():
        print(f"ERROR: {args.directory} is not a directory", file=sys.stderr)
        return 2

    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(message)s",
    )

    pdf_files = sorted(args.directory.rglob("*.pdf"))
    if not pdf_files:
        logger.warning("No PDFs found under %s", args.directory)
        return 0

    logger.info("Found %d PDFs under %s", len(pdf_files), args.directory)

    modified_count = 0
    error_count = 0

    with args.log.open("a", encoding="utf-8") as log_fh:
        for path in pdf_files:
            entry: dict[str, object] = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "file": str(path),
                "mode": "scan" if args.dry_run else "sanitize",
                "level": args.level,
            }

            if args.dry_run:
                report = scan(path)
                entry.update(report.as_dict())
                if report.risk_level != "none":
                    logger.info(
                        "  %s: %s (%s)",
                        path.name, report.risk_level,
                        ", ".join(report.annotation_action_types) or "none",
                    )
            else:
                sanitize_report = sanitize(path, return_report=True, level=args.level)
                entry.update(sanitize_report.as_dict())
                if sanitize_report.error:
                    error_count += 1
                    logger.warning("  %s: ERROR %s", path.name, sanitize_report.error)
                elif (
                    sanitize_report.javascript_in_names
                    or sanitize_report.open_action_removed
                    or sanitize_report.annotations_with_actions
                    or sanitize_report.dangerous_uris_removed
                ):
                    modified_count += 1
                    logger.info(
                        "  %s: cleaned (JS=%d, OA=%s, annot=%d, URIs=%d)",
                        path.name,
                        sanitize_report.javascript_in_names,
                        sanitize_report.open_action_removed,
                        sanitize_report.annotations_with_actions,
                        sanitize_report.dangerous_uris_removed,
                    )

            log_fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

    logger.info(
        "Done. %d files processed, %d had active content removed, %d errors. Log: %s",
        len(pdf_files), modified_count, error_count, args.log,
    )
    return 0 if error_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
