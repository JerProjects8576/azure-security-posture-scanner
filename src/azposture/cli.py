"""Command-line interface.

Exit codes: 0 = no findings at or above --fail-on, 1 = findings found, 2 = usage or input error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .models import Severity
from .reporters import FORMATS
from .rules import RULES
from .scanner import load_resources, scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="azposture",
        description="Scan Azure resources for common security misconfigurations.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--input", "-i", help="JSON file with resources (Resource Graph shape)")
    source.add_argument(
        "--subscription",
        "-s",
        action="append",
        help="scan a live subscription (repeat for several); needs azposture[live]",
    )
    parser.add_argument("--format", "-f", choices=sorted(FORMATS), default="table")
    parser.add_argument("--output", "-o", help="write the report to this file instead of stdout")
    parser.add_argument(
        "--min-severity",
        default="low",
        help="only report findings at or above this severity (default: low)",
    )
    parser.add_argument(
        "--fail-on",
        default="high",
        help="exit with code 1 if a finding at or above this severity exists (default: high)",
    )
    parser.add_argument("--list-rules", action="store_true", help="print all rules and exit")
    return parser


def _list_rules() -> str:
    lines = []
    for r, _ in RULES:
        lines.append(f"{r.id:<11} {r.severity.value:<9} {r.title}  [{r.mitre}]")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_rules:
        sys.stdout.write(_list_rules())
        return 0
    if not args.input and not args.subscription:
        parser.print_usage(sys.stderr)
        sys.stderr.write("azposture: error: give --input FILE or --subscription ID\n")
        return 2

    try:
        minimum = Severity.parse(args.min_severity)
        fail_on = Severity.parse(args.fail_on)
        if args.input:
            resources = load_resources(args.input)
        else:
            from .live import fetch_resources

            resources = fetch_resources(args.subscription)
    except (ValueError, RuntimeError) as exc:
        sys.stderr.write(f"azposture: error: {exc}\n")
        return 2

    result = scan(resources, minimum)
    report = FORMATS[args.format](result)
    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
    else:
        sys.stdout.write(report)

    return 1 if result.at_or_above(fail_on) else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
