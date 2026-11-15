"""Extensible argument validators used by policy-driven rule checks."""
from __future__ import annotations

import math
import re
from decimal import Decimal
from typing import Any

from firewall.cleaning import normalize_account, normalize_amount, normalize_path, normalize_recipient, normalize_url


class TypeViolation(ValueError):
    """A value failed a type-specific check; never embeds the value itself."""


class Validator:
    def __init__(self, function, constraint_keys=(), accepts=None):
        self.function = function
        self.constraint_keys = frozenset(constraint_keys)
        self.accepts = accepts

    def validate(self, value, spec, limits):
        return self.function(value, spec, limits)


_REGISTRY: dict[str, Any] = {}


def register_type(name: str, validator) -> None:
    """Register a validator object exposing validate(value, spec, limits)."""
    if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", name):
        raise ValueError("type name must be a lowercase identifier")
    if not callable(getattr(validator, "validate", None)):
        raise TypeError("validator must expose validate(value, spec, limits)")
    _REGISTRY[name] = validator


def get_validator(name):
    return _REGISTRY.get(name)


def registered_types():
    return frozenset(_REGISTRY)


def accepts_value(name, value):
    validator = get_validator(name)
    accepts = getattr(validator, "accepts", None)
    return True if accepts is None else bool(accepts(value))


def _generic(value, spec, limits):
    return value, None


def _recipient(value, spec, limits):
    if isinstance(value, list):
        normalized = [normalize_recipient(item) for item in value]
        if not value or any(item is None for item in normalized):
            return None, "INVALID_ARGUMENT_VALUE"
        return normalized, None
    result = normalize_recipient(value)
    return (result, None) if result else (None, "INVALID_ARGUMENT_VALUE")


def _amount(value, spec, limits):
    result = normalize_amount(value)
    return (result, None) if result is not None else (None, "INVALID_ARGUMENT_VALUE")


def _account(value, spec, limits):
    result = normalize_account(value)
    return (result, None) if result else (None, "INVALID_ARGUMENT_VALUE")


def _path(value, spec, limits):
    result = normalize_path(value)
    return (result, None) if result else (None, "INVALID_ARGUMENT_VALUE")


def _url(value, spec, limits):
    result = normalize_url(value)
    return (result, None) if result else (None, "INVALID_ARGUMENT_VALUE")


def _identifier(value, spec, limits):
    if isinstance(value, bool) or not (isinstance(value, str) or isinstance(value, int)):
        return None, "INVALID_ARGUMENT_VALUE"
    result = value.strip() if isinstance(value, str) else value
    return (result, None) if result != "" else (None, "INVALID_ARGUMENT_VALUE")


def _free_text(value, spec, limits):
    maximum = spec.constraints.get("max_length", 100000)
    if not isinstance(value, str) or len(value) > maximum:
        return None, "CONSTRAINT_VIOLATION"
    return value, None


def _numeric(value, spec, limits, *, integer):
    if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
        return None, "INVALID_ARGUMENT_VALUE"
    if integer and type(value) is not int:
        return None, "INVALID_ARGUMENT_VALUE"
    try:
        number = Decimal(str(value))
        if not number.is_finite():
            return None, "INVALID_ARGUMENT_VALUE"
        if "min" in spec.constraints and number < Decimal(str(spec.constraints["min"])):
            return None, "CONSTRAINT_VIOLATION"
        if "max" in spec.constraints and number > Decimal(str(spec.constraints["max"])):
            return None, "CONSTRAINT_VIOLATION"
    except Exception:
        return None, "INVALID_ARGUMENT_VALUE"
    return (int(value) if integer else float(number)), None


def _integer(value, spec, limits):
    return _numeric(value, spec, limits, integer=True)


def _number(value, spec, limits):
    return _numeric(value, spec, limits, integer=False)


def _enum(value, spec, limits):
    if not isinstance(value, str):
        return None, "INVALID_ARGUMENT_VALUE"
    if value not in spec.constraints.get("allowed_values", ()):
        return None, "CONSTRAINT_VIOLATION"
    return value, None


def _text_pattern(value, spec, limits):
    if not isinstance(value, str):
        return None, "INVALID_ARGUMENT_VALUE"
    if len(value) > spec.constraints.get("max_length", 100000):
        return None, "CONSTRAINT_VIOLATION"
    try:
        matched = re.fullmatch(spec.constraints["allowed_pattern"], value)
    except (re.error, KeyError):
        return None, "INVALID_ARGUMENT_VALUE"
    return (value, None) if matched else (None, "CONSTRAINT_VIOLATION")


for _name, _func, _keys, _accept in (
    ("recipient", _recipient, (), lambda v: isinstance(v, str) or (isinstance(v, list) and all(isinstance(item, str) for item in v))),
    ("amount", _amount, (), lambda v: not isinstance(v, bool) and isinstance(v, (str, int, float, Decimal))),
    ("account", _account, (), lambda v: isinstance(v, str)),
    ("path", _path, (), lambda v: isinstance(v, str)),
    ("url", _url, (), lambda v: isinstance(v, str)),
    ("identifier", _identifier, (), lambda v: isinstance(v, (str, int)) and not isinstance(v, bool)),
    ("free_text", _free_text, ("max_length",), lambda v: isinstance(v, str)),
    ("integer", _integer, ("min", "max"), lambda v: type(v) is int),
    ("number", _number, ("min", "max"), lambda v: not isinstance(v, bool) and isinstance(v, (int, float))),
    ("enum", _enum, ("allowed_values",), lambda v: isinstance(v, str)),
    ("text_pattern", _text_pattern, ("allowed_pattern", "max_length"), lambda v: isinstance(v, str)),
):
    register_type(_name, Validator(_func, _keys, _accept))
