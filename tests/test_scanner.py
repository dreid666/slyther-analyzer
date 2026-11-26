import json

from slyther_analyzer.cli import main
from slyther_analyzer.sarif import sarif_document
from slyther_analyzer.scanner import scan_path


def test_scanner_detects_evms_patterns(tmp_path):
    contract = tmp_path / "Treasury.sol"
    contract.write_text(
        "contract Treasury {\n"
        "  function transfer(address to) public { if (tx.origin == msg.sender) {} }\n"
        "  function destroy(address payable p) public { selfdestruct(p); }\n"
        "}\n",
        encoding="utf-8",
    )

    findings = scan_path(tmp_path)

    assert {finding.rule_id for finding in findings} == {
        "SLYTHER-EVM-001",
        "SLYTHER-EVM-003",
    }
    assert all(finding.line > 0 for finding in findings)


def test_scanner_is_deterministic_for_directory(tmp_path):
    (tmp_path / "b.sol").write_text("tx.origin;", encoding="utf-8")
    (tmp_path / "a.sol").write_text("delegatecall(0);", encoding="utf-8")

    first = scan_path(tmp_path)
    second = scan_path(tmp_path)

    assert [(finding.path, finding.rule_id, finding.line) for finding in first] == [
        (finding.path, finding.rule_id, finding.line) for finding in second
    ]


def test_sarif_has_required_structure(tmp_path):
    contract = tmp_path / "Treasury.sol"
    contract.write_text("tx.origin;", encoding="utf-8")
    document = sarif_document(scan_path(tmp_path))

    assert document["version"] == "2.1.0"
    assert "$schema" in document
    run = document["runs"][0]
    assert run["tool"]["driver"]["name"] == "Slyther Analyzer"
    assert run["tool"]["driver"]["rules"]
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


def test_cli_writes_sarif_and_returns_finding_status(tmp_path):
    contract = tmp_path / "Treasury.sol"
    contract.write_text("tx.origin;", encoding="utf-8")
    output = tmp_path / "results.sarif"

    assert main(["scan", str(contract), "--format", "sarif", "--output", str(output)]) == 1
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["runs"][0]["results"]


def test_cli_returns_zero_for_clean_target(tmp_path):
    contract = tmp_path / "Safe.sol"
    contract.write_text("contract Safe {}", encoding="utf-8")

    assert main(["scan", str(contract)]) == 0


def test_cli_returns_two_for_missing_target(tmp_path):
    assert main(["scan", str(tmp_path / "missing.sol")]) == 2


def test_benchmark_directory_reports_each_ecosystem():
    findings = scan_path("benchmarks")
    rule_ids = {finding.rule_id for finding in findings}
    assert "SLYTHER-EVM-001" in rule_ids
    assert "SLYTHER-COSMOS-001" in rule_ids
    assert "SLYTHER-BTC-001" in rule_ids


def test_scan_file_and_directory_public_helpers(tmp_path):
    from slyther_analyzer import scan_directory, scan_file

    contract = tmp_path / "Treasury.sol"
    contract.write_text("tx.origin;", encoding="utf-8")

    assert scan_file(contract)
    assert scan_directory(tmp_path)


def test_module_entry_point_runs(capsys):
    import runpy

    try:
        runpy.run_module("slyther_analyzer", run_name="__main__")
    except SystemExit as exc:
        assert exc.code == 2
