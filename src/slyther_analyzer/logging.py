"""Structured, tamper-evident audit logging."""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any


def sha256_file(path: str | Path) -> str | None:
    """Hash a file or create a deterministic hash of a directory tree."""
    try:
        source = Path(path)
        if source.is_file():
            return hashlib.sha256(source.read_bytes()).hexdigest()
        if source.is_dir():
            digest = hashlib.sha256()
            for item in sorted(source.rglob("*"), key=lambda candidate: candidate.as_posix()):
                if item.is_file():
                    relative = item.relative_to(source).as_posix()
                    digest.update(relative.encode("utf-8"))
                    digest.update(item.read_bytes())
            return digest.hexdigest()
        return None
    except OSError:
        return None


def audit(
    operation: str,
    status: str,
    *,
    target: str | None = None,
    findings: int | None = None,
    output: str | None = None,
    error: str | None = None,
    metadata: dict[str, Any] | None = None,
    log_file: str | Path | None = None,
) -> dict[str, Any]:
    """Write a JSON audit record and return it for verification."""
    record: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "operation": operation,
        "status": status,
        "verified": status == "success",
    }
    if target is not None:
        record["target"] = target
        record["target_sha256"] = sha256_file(target)
    if findings is not None:
        record["findings"] = findings
    if output is not None:
        record["output"] = output
        record["output_sha256"] = sha256_file(output)
    if error is not None:
        record["error"] = error
    if metadata:
        record["metadata"] = metadata

    line = json.dumps(record, sort_keys=True)
    destination = log_file or os.getenv("SLYTHER_AUDIT_LOG")
    if destination:
        path = Path(destination)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    else:
        sys.stderr.write(line + "\n")
    return record
