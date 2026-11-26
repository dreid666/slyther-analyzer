"""Tests for the Slyther Analyzer package metadata."""

import slyther_analyzer


def test_package_has_public_version():
    assert isinstance(slyther_analyzer.__version__, str)
    assert slyther_analyzer.__version__ == "0.1.0"


def test_package_name_matches_module():
    assert slyther_analyzer.__name__ == "slyther_analyzer"
