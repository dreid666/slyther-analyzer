"""Model Context Protocol server for Slyther Analyzer."""

from pathlib import Path

from mcp.server.fastmcp import FastMCP

from .agent import markdown_summary, scan_agent_target
from .logging import audit
from .sarif import sarif_document


mcp = FastMCP(
    "Slyther Security Agent",
    instructions=(
        "Scan blockchain source code for security issues. "
        "Use scan_target for a file or directory, or scan_changed_files "
        "for pull-request or commit-scoped analysis."
    ),
)


@mcp.tool()
def scan_target(target: str) -> dict:
    """Scan a file or directory and return findings as structured data."""
    path = Path(target)
    if not path.exists():
        audit("mcp.scan_target", "failure", target=target, error="target does not exist")
        return {"error": f"Target does not exist: {target}", "findings": []}

    findings = scan_agent_target(path)
    audit("mcp.scan_target", "success", target=str(path), findings=len(findings))
    return {
        "summary": markdown_summary(findings),
        "findings": [
            {
                "rule_id": finding.rule_id,
                "title": finding.title,
                "description": finding.description,
                "path": finding.path,
                "line": finding.line,
                "level": finding.level,
                "message": finding.message,
            }
            for finding in findings
        ],
        "sarif": sarif_document(findings),
    }


@mcp.tool()
def scan_changed_files(
    target: str,
    base: str | None = None,
    head: str | None = None,
) -> dict:
    """Scan source files changed between two Git revisions."""
    path = Path(target)
    if not path.exists():
        audit("mcp.scan_changed_files", "failure", target=target, error="target does not exist")
        return {"error": f"Target does not exist: {target}", "findings": []}

    findings = scan_agent_target(
        path,
        changed_only=True,
        base=base,
        head=head,
    )
    audit(
        "mcp.scan_changed_files",
        "success",
        target=str(path),
        findings=len(findings),
        metadata={"base": base, "head": head},
    )
    return {
        "summary": markdown_summary(findings),
        "findings": [
            {
                "rule_id": finding.rule_id,
                "title": finding.title,
                "description": finding.description,
                "path": finding.path,
                "line": finding.line,
                "level": finding.level,
                "message": finding.message,
            }
            for finding in findings
        ],
        "sarif": sarif_document(findings),
    }


@mcp.tool()
def agent_status() -> dict:
    """Return capabilities and supported source ecosystems."""
    status = {
        "name": "Slyther Security Agent",
        "supported_ecosystems": ["EVM", "Cosmos SDK", "Bitcoin"],
        "supported_extensions": [".sol", ".go", ".py", ".rs", ".js", ".ts"],
        "actions": ["scan_target", "scan_changed_files"],
    }
    audit("mcp.agent_status", "success", metadata=status)
    return status


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
