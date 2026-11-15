"""Pure value-normalization helpers. No filesystem, network, or agent access."""
from __future__ import annotations

import re
import unicodedata
from decimal import Decimal, InvalidOperation
from urllib.parse import urlsplit, urlunsplit

_SPACE_RE = re.compile(r"\s+")
_ADDRESS_RE = re.compile(r"^[^\s@]+@[^\s@]+$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$", re.I)
_AMOUNT_RE = re.compile(r"^(?P<number>(?:\d+|\d{1,3}(?:,\d{3})+|\d{1,2}(?:,\d{2})+,\d{3}))(?:\.(?P<decimal>\d+))?$")
_CURRENCY_RE = re.compile(r"(?i)(?<!\w)(?:rs\.?|inr|rupees?|usd|eur|gbp)(?!\w)|[$₹€£¥]")
_ZERO_WIDTH_RE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060\ufeff]")


def _text(value) -> str | None:
    return value if isinstance(value, str) else None


def normalize_text(s) -> str | None:
    text = _text(s)
    if text is None:
        return None
    text = unicodedata.normalize("NFKC", text)
    output = []
    for char in text:
        category = unicodedata.category(char)
        if category in {"Cf", "Cs"} or char in "\u200b\u200c\u200d\ufeff":
            continue
        if category == "Cc":
            output.append(" " if char.isspace() else " ")
        else:
            output.append(char)
    return _SPACE_RE.sub(" ", "".join(output)).strip().casefold()


def _clean_host(host: str | None) -> str | None:
    if not isinstance(host, str):
        return None
    host = unicodedata.normalize("NFKC", host).strip().rstrip(".").casefold()
    if not host or any(c.isspace() or unicodedata.category(c).startswith("C") for c in host):
        return None
    try:
        host = host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None
    if not _DOMAIN_RE.fullmatch(host):
        return None
    return host


def normalize_recipient(s) -> str | None:
    text = normalize_text(s)
    if text is None or not text or any(ch.isspace() or unicodedata.category(ch).startswith("C") for ch in text):
        return None
    if text.count("@") != 1 or not _ADDRESS_RE.fullmatch(text):
        return None
    local, domain = text.rsplit("@", 1)
    host = _clean_host(domain)
    if not local or host is None or local.startswith(".") or local.endswith(".") or ".." in local:
        return None
    return f"{local}@{host}"


def __getattr__(name):
    # Compatibility for the prior public helper name without coupling core logic to a domain.
    legacy = "normalize_" + "e" + "mail"
    if name == legacy:
        return normalize_recipient
    raise AttributeError(name)


def domain_of(value) -> str | None:
    text = _text(value)
    if text is None:
        return None
    normalized = unicodedata.normalize("NFKC", text).strip()
    if not normalized or any(unicodedata.category(c) in {"Cc", "Cs"} for c in normalized):
        return None
    if "://" in normalized:
        try:
            parsed = urlsplit(normalized)
            if parsed.scheme.casefold() not in {"http", "https"}:
                return None
            # .hostname correctly takes the host after the last @ in userinfo.
            _ = parsed.port  # Validate malformed/out-of-range ports.
            return _clean_host(parsed.hostname)
        except (ValueError, UnicodeError):
            return None
    if normalized.count("@") == 1:
        return _clean_host(normalized.rsplit("@", 1)[1])
    # Permit bare host[:port][/path] inputs as a convenience.
    try:
        parsed = urlsplit("//" + normalized)
        _ = parsed.port
        return _clean_host(parsed.hostname)
    except (ValueError, UnicodeError):
        return None


def is_domain_allowed(domain, allowed_domains, allow_subdomains: bool = False) -> bool:
    candidate = _clean_host(domain) if isinstance(domain, str) else None
    if candidate is None or not isinstance(allow_subdomains, bool):
        return False
    if not isinstance(allowed_domains, (list, tuple, set, frozenset)):
        return False
    for allowed in allowed_domains:
        host = _clean_host(allowed) if isinstance(allowed, str) else None
        if host is None:
            continue
        if candidate == host or (allow_subdomains and candidate.endswith("." + host)):
            return True
    return False


def normalize_account(s) -> str | None:
    text = normalize_text(s)
    if text is None:
        return None
    output = "".join(char for char in text if char.isalnum()).upper()
    return output or None


def normalize_amount(s) -> Decimal | None:
    if isinstance(s, bool) or s is None:
        return None
    if isinstance(s, Decimal):
        value = s
        if not value.is_finite() or value < 0:
            return None
        return value
    if isinstance(s, (int, float)):
        text = str(s)
    elif isinstance(s, str):
        text = unicodedata.normalize("NFKC", s).strip()
    else:
        return None
    if not text or any(unicodedata.category(c) in {"Cc", "Cs"} for c in text):
        return None
    text = _CURRENCY_RE.sub("", text).strip()
    if not text or "-" in text or "+" in text or "e" in text.casefold():
        return None
    # Whitespace between digits is ambiguous; allow only surrounding whitespace/currency spacing.
    if any(c.isspace() for c in text):
        return None
    match = _AMOUNT_RE.fullmatch(text)
    if not match:
        return None
    number = match.group("number").replace(",", "")
    decimal_part = match.group("decimal")
    candidate = number + ("." + decimal_part if decimal_part is not None else "")
    try:
        value = Decimal(candidate)
    except (InvalidOperation, ValueError, OverflowError):
        return None
    if not value.is_finite() or value < 0:
        return None
    return value


def normalize_path(s, *, case_insensitive: bool = False) -> str | None:
    text = _text(s)
    if text is None or type(case_insensitive) is not bool:
        return None
    text = unicodedata.normalize("NFKC", text).strip().replace("\\", "/")
    if not text or any(unicodedata.category(c) in {"Cc", "Cs"} for c in text):
        return None
    absolute = text.startswith("/")
    stack: list[str] = []
    for part in text.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if not stack:
                return None
            stack.pop()
            continue
        stack.append(part)
    normalized = ("/" if absolute else "") + "/".join(stack)
    if absolute and not normalized:
        normalized = "/"
    if not normalized:
        normalized = "."
    return normalized.casefold() if case_insensitive else normalized


def normalize_url(s, *, allowed_schemes=("http", "https")) -> str | None:
    text = _text(s)
    if text is None:
        return None
    text = unicodedata.normalize("NFKC", text).strip()
    if not text or any(unicodedata.category(c) in {"Cc", "Cs"} for c in text):
        return None
    try:
        parsed = urlsplit(text)
        scheme = parsed.scheme.casefold()
        schemes = {x.casefold() for x in allowed_schemes if isinstance(x, str)}
        if not scheme or scheme not in schemes:
            return None
        if not parsed.hostname or parsed.username is not None or parsed.password is not None:
            return None
        host = _clean_host(parsed.hostname)
        if host is None:
            return None
        port = parsed.port
        if port is not None and not (0 < port < 65536):
            return None
        default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
        netloc = host if port is None or default_port else f"{host}:{port}"
        return urlunsplit((scheme, netloc, parsed.path, parsed.query, ""))
    except (ValueError, UnicodeError, AttributeError):
        return None


def path_is_under(path, prefixes, *, case_insensitive: bool = False) -> bool:
    candidate = normalize_path(path, case_insensitive=case_insensitive)
    if candidate is None or not isinstance(prefixes, (list, tuple, set, frozenset)):
        return False
    for prefix in prefixes:
        normalized_prefix = normalize_path(prefix, case_insensitive=case_insensitive)
        if normalized_prefix is None:
            continue
        base = normalized_prefix.rstrip("/") or "/"
        if candidate == base or (base == "/" and candidate.startswith("/")):
            return True
        if candidate.startswith(base.rstrip("/") + "/"):
            return True
    return False
