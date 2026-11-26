"""GitHub Actions agent behavior for pull request and push scans."""

from pathlib import Path
import os
import subprocess

from .sarif import dumps_sarif
from .scanner import Finding, scan_path


SUPPORTED_SUFFIXES = {".sol", ".go", ".py", ".rs", ".js", ".ts"}


def changed_source_files(
    repository: Path,
    base: str | None = None,
    head: str | None = None,
) -> list[Path]:
    """Return source files changed between Git revisions."""
    head = head or "HEAD"
    range_args = [base, head] if base else ["HEAD^", head]
    try:
        root_result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
        )
        root = Path(root_result.stdout.strip())
        result = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACMR", *range_args, "--"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []

    files = []
    for name in result.stdout.splitlines():
        path = root / name
        if path.suffix.lower() in SUPPORTED_SUFFIXES and path.is_file():
            files.append(path)
    return files


def scan_agent_target(
    target: str | Path,
    *,
    changed_only: bool = False,
    base: str | None = None,
    head: str | None = None,
) -> list[Finding]:
    """Scan a target, optionally restricting results to changed source files."""
    root = Path(target)
    if not changed_only:
        return scan_path(root)

    repository = root if root.is_dir() else root.parent
    findings = []
    for path in changed_source_files(repository, base, head):
        if root.is_file() and path != root.resolve():
            continue
        if root.is_dir() and not path.resolve().is_relative_to(root.resolve()):
            continue
        try:
            findings.extend(scan_path(path))
        except (OSError, UnicodeDecodeError):
            continue
    return sorted(
        set(findings),
        key=lambda finding: (finding.path, finding.line, finding.rule_id),
    )


def markdown_summary(findings: list[Finding]) -> str:
    if not findings:
        return "## Slyther Agent\n\nNo security findings detected."

    lines = [
        "## Slyther Agent",
        "",
        f"Found **{len(findings)}** potential security issue(s).",
        "",
        "| Severity | Location | Rule | Finding |",
        "| --- | --- | --- | --- |",
    ]
    for finding in findings:
        location = f"{finding.path}:{finding.line}"
        finding_text = finding.message.replace("|", "\\|").replace("\n", " ")
        lines.append(
            f"| {finding.level} | `{location}` | `{finding.rule_id}` | {finding_text} |"
        )
    return "\n".join(lines)


def write_github_outputs(output_path: str, findings: list[Finding]) -> None:
    github_output = os.getenv("GITHUB_OUTPUT")
    if not github_output:
        return
    with open(github_output, "a", encoding="utf-8") as handle:
        handle.write(f"sarif={output_path}\n")
        handle.write(f"findings={len(findings)}\n")


def write_github_summary(findings: list[Finding]) -> None:
    github_summary = os.getenv("GITHUB_STEP_SUMMARY")
    if not github_summary:
        return
    with open(github_summary, "a", encoding="utf-8") as handle:
        handle.write(markdown_summary(findings) + "\n")


def emit_github_annotations(findings: list[Finding]) -> None:
    for finding in findings:
        command = "error" if finding.level == "error" else "warning"
        print(
            f"::{command} file={finding.path},line={finding.line},"
            f"title={finding.rule_id}::{finding.message}"
        )
