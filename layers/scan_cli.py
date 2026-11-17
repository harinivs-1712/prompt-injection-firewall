"""Compatibility alias for firewall.layer1.scan_cli."""
import importlib as _importlib
import sys as _sys

_module = _importlib.import_module("firewall.layer1.scan_cli")
if __name__ == "__main__":
    raise SystemExit(_module.main())
_sys.modules[__name__] = _module
