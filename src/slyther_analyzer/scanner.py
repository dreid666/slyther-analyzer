"""Deterministic heuristic rules for blockchain source files."""

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Iterable


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    description: str
    path: str
    line: int
    message: str
    level: str = "warning"


RULES = (
    {
        "id": "SLYTHER-EVM-001",
        "title": "Transaction origin used for authorization",
        "pattern": r"\btx\.origin\b",
        "description": "tx.origin is unsuitable for authorization because intermediary contracts can trigger calls.",
        "ecosystem": ("sol",),
    },
    {
        "id": "SLYTHER-EVM-002",
        "title": "Unrestricted delegatecall",
        "pattern": r"\bdelegatecall\s*\(",
        "description": "Delegatecall executes external code in the caller's storage context.",
        "ecosystem": ("sol",),
    },
    {
        "id": "SLYTHER-EVM-003",
        "title": "Use of selfdestruct",
        "pattern": r"\b(?:selfdestruct|suicide)\s*\(",
        "description": "Contract destruction can make addresses and pending calls permanently unusable.",
        "ecosystem": ("sol",),
    },
    {
        "id": "SLYTHER-COSMOS-001",
        "title": "Unchecked bech32 address conversion",
        "pattern": r"\bAccAddressFrom(?:Bech32|Bech32WithPrefix)\s*\([^,;\n]*\)",
        "description": "Address conversion errors should be handled before the value is used.",
        "ecosystem": ("go",),
    },
    {
        "id": "SLYTHER-COSMOS-002",
        "title": "Ignored panic recovery in begin block",
        "pattern": r"BeginBlock(?:er)?\s*\([^)]*\)",
        "description": "Review begin-block handlers for panic and state-consistency behavior.",
        "ecosystem": ("go",),
    },
    {
        "id": "SLYTHER-BTC-001",
        "title": "Weak Bitcoin script pattern",
        "pattern": r"\b(?:OP_VERIFY|OP_CHECKSIG)\b",
        "description": "Verify Bitcoin script branching and signature checks carefully.",
        "ecosystem": ("py", "rs", "js", "ts"),
    },
)


def iter_source_files(target: Path) -> Iterable[Path]:
    if target.is_file():
        return (target,)
    suffixes = {f".{ecosystem}" for rule in RULES for ecosystem in rule["ecosystem"]}
    return (
        path
        for path in target.rglob("*")
        if path.is_file() and path.suffix.lower() in suffixes
    )


def scan_path(target: str | Path) -> list[Finding]:
    root = Path(target)
    findings: list[Finding] = []
    for path in sorted(iter_source_files(root)):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue

        relative = path.as_posix()
        for rule in RULES:
            if path.suffix.lower().lstrip(".") not in rule["ecosystem"]:
                continue
            for match in re.finditer(rule["pattern"], text):
                line = text.count("\n", 0, match.start()) + 1
                findings.append(
                    Finding(
                        rule_id=rule["id"],
                        title=rule["title"],
                        description=rule["description"],
                        path=relative,
                        line=line,
                        message=f"{rule['title']}: {rule['description']}",
                    )
                )
    return findings


def scan_file(target: str | Path) -> list[Finding]:
    """Scan one source file."""
    path = Path(target)
    if not path.is_file():
        return []
    return scan_path(path)


def scan_directory(target: str | Path) -> list[Finding]:
    """Scan all supported source files below a directory."""
    path = Path(target)
    if not path.is_dir():
        return []
    return scan_path(path)
