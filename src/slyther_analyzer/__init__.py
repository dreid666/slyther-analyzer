"""Slyther Analyzer open-source static security scanner."""

__version__ = "0.1.0"

from .scanner import Finding, scan_directory, scan_file, scan_path

__all__ = (
    "__version__",
    "Finding",
    "scan_directory",
    "scan_file",
    "scan_path",
)
