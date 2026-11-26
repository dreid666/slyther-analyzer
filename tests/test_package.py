"""Tests for the Slyther Analyzer package metadata."""

import slyther_analyzer


def test_package_has_public_version():
    assert isinstance(slyther_analyzer.__version__, str)
    assert slyther_analyzer.__version__ == "1.0.1"


def test_package_name_matches_module():
    assert slyther_analyzer.__name__ == "slyther_analyzer"


def test_public_scanner_api_is_exported():
    assert slyther_analyzer.Finding
    assert callable(slyther_analyzer.scan_path)
    assert callable(slyther_analyzer.scan_directory)
    assert callable(slyther_analyzer.scan_file)
