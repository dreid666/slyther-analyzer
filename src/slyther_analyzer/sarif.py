"""SARIF v2.1.0 serialization."""

import json
from typing import Iterable

from .scanner import Finding


def sarif_document(findings: Iterable[Finding]) -> dict:
    findings = list(findings)
    rules: dict[str, dict] = {}
    results = []

    for finding in findings:
        if finding.rule_id not in rules:
            rules[finding.rule_id] = {
                "id": finding.rule_id,
                "name": finding.rule_id,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "defaultConfiguration": {"level": finding.level},
            }
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": finding.level,
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.path},
                            "region": {"startLine": finding.line},
                        }
                    }
                ],
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Slyther Analyzer",
                        "version": "1.0.0",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def dumps_sarif(findings: Iterable[Finding]) -> str:
    return json.dumps(sarif_document(findings), indent=2) + "\n"
