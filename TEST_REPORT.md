# Test Run Report

- Repository: `dreid666/slyther-analyzer`
- Checked: 2026-11-26
- Status: **Passing**
- Results: **12 passed; 94% coverage**
- Package verification:
  - Editable install passed
  - Wheel and source distributions built successfully
  - `twine check` passed for both distributions
  - Clean virtual-environment wheel smoke test passed

## Certification

- Level: **Certified Platinum**
- Certification period: **90 days**
- Certified: **2026-11-26**
- Valid through: **2027-02-24**
- Verified:
  - `python -m pip install -e ".[dev]"`
  - `pytest -q`
  - `flake8 src tests --count --select=E9,F63,F7,F82 --show-source --statistics`
  - `python -m build`
  - `slyther-analyzer --version`

The test suite covers package metadata, deterministic scanner rules, SARIF v2.1.0 structure,
CLI output and exit codes, and missing/clean scan targets.
