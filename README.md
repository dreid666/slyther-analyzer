# Slyther Analyzer

Open-source Python static security scanner for smart contract and blockchain codebases, emitting **SARIF v2.1.0** for GitHub Code Scanning.

## Install & Run

```bash
pip install -e ".[dev]"
slyther-analyzer scan benchmarks --format sarif --output results.sarif
pytest
```

## Layout

- `src/slyther_analyzer/` — CLI entry point, heuristic rule scanner, and SARIF v2.1.0 emitter.
- `benchmarks/` — Synthetic benchmark fixtures and expected results.
- `action.yml` and `.github/workflows/slyther-analyzer.yml` — GitHub Action and PR scanning workflow.
- `tests/` — Regression tests for benchmark detection, SARIF structure, and CLI exit codes.

## License

MIT License

Copyright (c) 2026 Daniel James Reid
