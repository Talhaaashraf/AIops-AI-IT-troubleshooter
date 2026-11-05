"""Shared, allow-listed diagnose/fix toolkit used by the AIops server and agents."""

from . import component_tests, diagnostics, hardware, leftovers, microsoft, remediation, software, threats, updates  # noqa: F401  (importing registers the tools)
from .registry import RISK_LEVELS, describe_tools, get_tool, list_tools, risk_rank, run_tool, tool_schemas

TOOLKIT_VERSION = "1.9.0"

__all__ = ["RISK_LEVELS", "TOOLKIT_VERSION", "describe_tools", "get_tool", "list_tools", "risk_rank", "run_tool", "tool_schemas"]
