"""
Read-only audit of PDFs in a directory. Produces a risk report without
modifying any files.

Output: human-readable summary to stdout, JSON detail to --json file.

Usage:
    python examples/audit_only.py /path/to/pdfs
    python examples/audit_only.py /path/to/pdfs --json findings.json
    python examples/audit_only.py /path/to/pdfs --filter high  # only high-risk
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from pdf_defang import scan


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="Directory to scan")
    parser.add_argument("--json", type=Path, help="Write JSON output to file")
    parser.add_argument(
        "--filter", choices=["all", "low", "medium", "high"], default="all",
        help="Only show files at this risk level or above (default: all)",
    )
    args = parser.parse_args()

    if not args.directory.is_dir():
        print(f"ERROR: {args.directory} is not a directory", file=sys.stderr)
        return 2

    pdf_files = sorted(args.directory.rglob("*.pdf"))
    if not pdf_files:
        print("No PDFs found.")
        return 0

    risk_order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    min_risk = risk_order.get(args.filter, 0)

    findings: list[dict[str, object]] = []
    counts: Counter[str] = Counter()

    print(f"Scanning {len(pdf_files)} PDFs under {args.directory}...\n")

    for path in pdf_files:
        report = scan(path)
        counts[report.risk_level] += 1

        if risk_order[report.risk_level] >= min_risk:
            findings.append({"file": str(path), **report.as_dict()})

            if report.risk_level != "none":
                print(f"  [{report.risk_level.upper():6s}] {path.name}")
                if report.has_javascript:
                    print(f"          - document JavaScript ({report.javascript_in_names} entries)")
                if report.has_open_action:
                    print("          - /OpenAction set")
                if report.has_xfa_form:
                    print("          - XFA form")
                if report.annotation_action_types:
                    print(f"          - dangerous annotation actions: {', '.join(report.annotation_action_types)}")
                if report.dangerous_uris:
                    print(f"          - dangerous URIs ({', '.join(report.dangerous_uri_schemes)})")

    print("\nSummary:")
    print(f"  Total PDFs scanned: {len(pdf_files)}")
    for level in ("high", "medium", "low", "none"):
        n = counts.get(level, 0)
        if n:
            print(f"  {level:6s}: {n}")

    if args.json:
        args.json.write_text(json.dumps(findings, indent=2), encoding="utf-8")
        print(f"\nJSON output written to {args.json}")

    return 0 if counts.get("high", 0) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
