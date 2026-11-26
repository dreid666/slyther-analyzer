# Slyther Analyzer

Open-source Python static security scanner for smart contract and blockchain codebases, emitting **SARIF v2.1.0** for GitHub Code Scanning.

## Install & Run

```bash
pip install slyther-analyzer
slyther-analyzer scan benchmarks --format sarif --output results.sarif
pytest
```

For MCP support:

```bash
pip install "slyther-analyzer[mcp]"
```

Python 3.10 through 3.14 are supported and tested runtimes. The CLI uses exit code `0`
for a clean scan, `1` when findings are present, and `2` for invalid targets.

## GitHub Actions Agent

Use the repository as an agent in pull requests or pushes:

```yaml
- uses: dreid666/slyther-analyzer@main
  with:
    target: .
    output: slyther-analyzer.sarif
```

The agent scans changed source files on pull requests, writes a GitHub Step Summary,
publishes workflow annotations, and returns the SARIF path plus finding count as outputs.

## MCP Agent

Install the MCP extra, then use the server from VS Code or another MCP client:

```bash
pip install -e ".[mcp]"
slyther-analyzer-mcp
```

VS Code discovers the workspace server from `.vscode/mcp.json`. The server exposes
`scan_target`, `scan_changed_files`, and `agent_status` tools.

## Verified audit logging

All CLI, GitHub Agent, and MCP scan operations write structured JSON audit records.
Set `SLYTHER_AUDIT_LOG=/path/to/audit.jsonl`, or pass `--log-file` to a CLI command:

```bash
slyther-analyzer scan benchmarks --log-file audit.jsonl
slyther-analyzer agent benchmarks --log-file audit.jsonl
```

Records include UTC timestamps, operation/status, target and output SHA-256 hashes,
finding counts, and a `verified` success marker.

## Layout

- `src/slyther_analyzer/` — CLI entry point, heuristic rule scanner, and SARIF v2.1.0 emitter.
- `benchmarks/` — Synthetic benchmark fixtures and expected results.
- `action.yml` and `.github/workflows/slyther-analyzer.yml` — GitHub Action and PR scanning workflow.
- `tests/` — Regression tests for benchmark detection, SARIF structure, and CLI exit codes.

## License

MIT License

Copyright (c) 2026 Daniel James Reid
