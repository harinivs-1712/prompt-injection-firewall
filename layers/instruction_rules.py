"""Compatibility alias for firewall.layer1.instruction_rules."""
import importlib as _importlib
import sys as _sys

_module = _importlib.import_module("firewall.layer1.instruction_rules")
_sys.modules[__name__] = _module
