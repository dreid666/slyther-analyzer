"""Command-line interface for Slyther Analyzer."""

import argparse
import sys
from pathlib import Path

from . import __version__
from .sarif import dumps_sarif
from .scanner import scan_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="slyther-analyzer",
        description="Deterministic static security scanner for blockchain code.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subcommands = parser.add_subparsers(dest="command", required=True)

    scan = subcommands.add_parser("scan", help="scan a file or directory")
    scan.add_argument("target", help="source file or directory")
    scan.add_argument("--format", choices=("sarif", "text"), default="text")
    scan.add_argument("--output", help="write results to this file")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        target = Path(args.target)
        if not target.exists():
            print(f"error: target does not exist: {target}", file=sys.stderr)
            return 2

        findings = scan_path(target)
        if args.format == "sarif":
            rendered = dumps_sarif(findings)
        else:
            if findings:
                rendered = "\n".join(
                    f"{finding.path}:{finding.line}: [{finding.rule_id}] {finding.message}"
                    for finding in findings
                ) + "\n"
            else:
                rendered = "No findings.\n"

        if args.output:
            output = Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
        return 1 if findings else 0
    return 0
