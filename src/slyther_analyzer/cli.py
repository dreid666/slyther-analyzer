"""Command-line interface for Slyther Analyzer."""

import argparse
import sys
from pathlib import Path

from . import __version__
from .logging import audit
from .agent import (
    emit_github_annotations,
    markdown_summary,
    scan_agent_target,
    write_github_outputs,
    write_github_summary,
)
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
    scan.add_argument("--log-file", help="append structured audit records")

    agent = subcommands.add_parser(
        "agent",
        help="run the GitHub Actions agent workflow",
    )
    agent.add_argument("target", nargs="?", default=".")
    agent.add_argument("--base", help="base Git revision for changed-file scans")
    agent.add_argument("--head", help="head Git revision for changed-file scans")
    agent.add_argument(
        "--changed-only",
        action="store_true",
        help="scan only source files changed between base and head",
    )
    agent.add_argument(
        "--output",
        default="slyther-analyzer.sarif",
        help="write the SARIF report to this path",
    )
    agent.add_argument(
        "--fail-on",
        choices=("none", "warning", "error"),
        default="warning",
        help="exit non-zero when findings meet this severity",
    )
    agent.add_argument("--log-file", help="append structured audit records")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        target = Path(args.target)
        if not target.exists():
            audit("cli.scan", "failure", target=str(target), error="target does not exist", log_file=getattr(args, "log_file", None))
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
        status = 1 if findings else 0
        audit(
            "cli.scan",
            "success",
            target=str(target),
            findings=len(findings),
            output=str(output) if args.output else None,
            metadata={"format": args.format, "exit_code": status},
            log_file=args.log_file,
        )
        return status
    if args.command == "agent":
        target = Path(args.target)
        if not target.exists():
            audit("cli.agent", "failure", target=str(target), error="target does not exist", log_file=args.log_file)
            print(f"error: target does not exist: {target}", file=sys.stderr)
            return 2

        findings = scan_agent_target(
            target,
            changed_only=args.changed_only,
            base=args.base,
            head=args.head,
        )
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(dumps_sarif(findings), encoding="utf-8")

        print(markdown_summary(findings))
        write_github_summary(findings)
        write_github_outputs(str(output), findings)
        emit_github_annotations(findings)

        should_fail = args.fail_on != "none" and bool(findings)
        if should_fail and args.fail_on == "error":
            should_fail = any(finding.level == "error" for finding in findings)
        status = 1 if should_fail else 0
        audit(
            "cli.agent",
            "success",
            target=str(target),
            findings=len(findings),
            output=str(output),
            metadata={"changed_only": args.changed_only, "exit_code": status},
            log_file=args.log_file,
        )
        return status
    return 0
