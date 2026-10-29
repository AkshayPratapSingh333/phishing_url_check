"""
CLI entry point for the Phishing URL Awareness Checker.

Supports two modes:
    1. **Interactive** (default): prompts for a URL and prints results.
    2. **Direct**: pass the URL as a command-line argument.

Usage::

    python -m src.cli
    python -m src.cli "http://example.com@evil.invalid"
    python -m src.cli --help
    python -m src.cli --list-rules
"""

from __future__ import annotations

import argparse
import sys

from src import __version__
from src.formatter import Formatter
from src.inspector import inspect_url
from src.rules.registry import list_rule_summaries


def _build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="phishing-checker",
        description=(
            "EWB Phishing URL Awareness Checker v{ver}\n"
            "Reads URL text for selected warning signs.\n"
            "Does NOT visit websites, scan for malware, or prove safety."
        ).format(ver=__version__),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "url",
        nargs="?",
        default=None,
        help="URL string to inspect (omit for interactive mode).",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable coloured output.",
    )
    parser.add_argument(
        "--list-rules",
        action="store_true",
        help="Print a table of all registered rules and exit.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def _print_rules_table(formatter: Formatter) -> None:
    """Print a summary table of all registered rules."""
    rules = list_rule_summaries()
    print()
    header = f"  {'ID':<16} {'Name':<28} {'Severity':<10}"
    print(header)
    print("  " + "─" * 56)
    for r in rules:
        print(f"  {r['rule_id']:<16} {r['name']:<28} {r['severity']:<10}")
    print()


def main(argv: list[str] | None = None) -> int:
    """
    CLI entry point.

    Returns an exit code: 0 for success, 1 for errors.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    use_colour = False if args.no_color else None
    fmt = Formatter(use_colour=use_colour)

    if args.list_rules:
        _print_rules_table(fmt)
        return 0

    fmt.print_banner()

    # ── Get URL input ─────────────────────────────────────────
    if args.url:
        raw_url = args.url
    else:
        try:
            raw_url = input("  Enter a URL to inspect: ")
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

    # ── Inspect & display ─────────────────────────────────────
    result = inspect_url(raw_url)
    fmt.print_result(result)

    # Return non-zero if warnings were found (useful for scripting)
    return 1 if result.has_warnings else 0


if __name__ == "__main__":
    sys.exit(main())
