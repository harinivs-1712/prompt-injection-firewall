"""Compatibility package; use firewall.layer1 for new imports."""
import warnings as _warnings

_warnings.warn(
    "The layers package is deprecated; import from firewall.layer1 instead.",
    DeprecationWarning,
    stacklevel=2,
)
