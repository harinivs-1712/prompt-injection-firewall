"""Environment and command-line settings for the local review server."""
from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from pathlib import Path

WEAK_TOKENS = {
    "password", "changeme", "token", "viewer", "reviewer", "agent", "admin", "secret", "123456",
    "password" * 3, "password" * 4, "changeme" * 3, "123456" * 4, "admin" * 5,
}


@dataclass(frozen=True)
class Settings:
    audit_db: Path
    review_db: Path
    policy: Path
    viewer_token: str
    reviewer_token: str
    cors_origins: tuple[str, ...]
    host: str = "127.0.0.1"
    port: int = 8000
    store_text: bool = False
    retention_hours: int = 24
    enable_docs: bool = False
    allow_remote: bool = False
    allowed_hosts: tuple[str, ...] = ()
    audit_verify_cap: int = 100_000
    enable_broker: bool = False
    agent_token: str = ""
    broker_max_pending: int = 100
    broker_max_ttl_seconds: float = 300.0
    broker_body_max_bytes: int = 65536


def _env(name: str, default: str | None = None) -> str | None:
    return os.environ.get(name, default)


def _bool(value: str | bool | None) -> bool:
    return str(value or "0").strip().casefold() in {"1", "true", "yes", "on"}


def _tokens_ok(viewer: str, reviewer: str, agent: str = "", *, broker_enabled: bool = False) -> str | None:
    tokens = [("viewer", viewer), ("reviewer", reviewer)]
    if broker_enabled:
        tokens.append(("agent", agent))
    for label, token in tokens:
        if len(token) < 24 or token.casefold() in WEAK_TOKENS:
            return f"{label} token must be at least 24 characters and not an obvious weak value"
    if viewer == reviewer:
        return "viewer and reviewer tokens must differ"
    if broker_enabled:
        if agent == viewer:
            return "agent and viewer tokens must differ"
        if agent == reviewer:
            return "agent and reviewer tokens must differ"
    return None


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Local read-only firewall review API")
    p.add_argument("--audit-db", default=_env("FIREWALL_AUDIT_DB"))
    p.add_argument("--review-db", default=_env("FIREWALL_REVIEW_DB"))
    p.add_argument("--policy", default=_env("FIREWALL_POLICY"))
    p.add_argument("--host", default=_env("FIREWALL_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(_env("FIREWALL_PORT", "8000")))
    p.add_argument("--cors-origins", default=_env("FIREWALL_CORS_ORIGINS"))
    p.add_argument("--store-text", action="store_true", default=_bool(_env("FIREWALL_REVIEW_STORE_TEXT")))
    p.add_argument("--retention-hours", type=int, default=int(_env("FIREWALL_REVIEW_RETENTION_HOURS", "24")))
    p.add_argument("--enable-docs", action="store_true", default=_bool(_env("FIREWALL_ENABLE_DOCS")))
    p.add_argument("--allow-remote", action="store_true")
    p.add_argument("--enable-broker", action="store_true", default=_bool(_env("FIREWALL_ENABLE_BROKER")))
    p.add_argument("--broker-max-pending", type=int, default=int(_env("FIREWALL_BROKER_MAX_PENDING", "100")))
    p.add_argument("--broker-max-ttl-seconds", type=float, default=float(_env("FIREWALL_BROKER_MAX_TTL_SECONDS", "300")))
    p.add_argument("--broker-body-max-bytes", type=int, default=int(_env("FIREWALL_BROKER_BODY_MAX_BYTES", "65536")))
    return p


def from_args(argv=None) -> Settings:
    args = parser().parse_args(argv)
    missing = [name for name, value in (("FIREWALL_AUDIT_DB/--audit-db", args.audit_db),
                                        ("FIREWALL_REVIEW_DB/--review-db", args.review_db),
                                        ("FIREWALL_POLICY/--policy", args.policy),
                                        ("FIREWALL_VIEWER_TOKEN", _env("FIREWALL_VIEWER_TOKEN")),
                                        ("FIREWALL_REVIEWER_TOKEN", _env("FIREWALL_REVIEWER_TOKEN"))) if not value]
    if missing:
        raise ValueError("Missing required settings: " + ", ".join(missing))

    viewer, reviewer = _env("FIREWALL_VIEWER_TOKEN", ""), _env("FIREWALL_REVIEWER_TOKEN", "")
    agent = _env("FIREWALL_AGENT_TOKEN", "")
    enable_broker = args.enable_broker

    if enable_broker and not agent:
        raise ValueError("FIREWALL_AGENT_TOKEN is required when broker is enabled")

    token_error = _tokens_ok(viewer, reviewer, agent, broker_enabled=enable_broker)
    if token_error:
        raise ValueError(token_error)

    host = str(args.host)
    if host not in {"127.0.0.1", "localhost", "::1"} and not args.allow_remote:
        raise ValueError("Refusing non-local host without --allow-remote")

    audit, review, policy = Path(args.audit_db), Path(args.review_db), Path(args.policy)
    if not audit.is_file():
        raise ValueError("Audit database does not exist")
    if not review.is_file():
        raise ValueError("Review database does not exist")
    if not policy.is_file():
        raise ValueError("Policy file does not exist")

    if args.port < 1 or args.port > 65535 or args.retention_hours < 1:
        raise ValueError("port and retention hours must be positive")
    if args.broker_max_pending < 1 or args.broker_max_ttl_seconds <= 0 or args.broker_body_max_bytes < 1:
        raise ValueError("broker queue settings must be positive")

    origin_value = args.cors_origins or "http://localhost:5173,http://127.0.0.1:5173"
    origins = tuple(x.strip() for x in origin_value.split(",") if x.strip())
    allowed = tuple(x.strip() for x in _env("FIREWALL_ALLOWED_HOSTS", "").split(",") if x.strip())

    return Settings(
        audit_db=audit,
        review_db=review,
        policy=policy,
        viewer_token=viewer,
        reviewer_token=reviewer,
        cors_origins=origins,
        host=host,
        port=args.port,
        store_text=args.store_text,
        retention_hours=args.retention_hours,
        enable_docs=args.enable_docs,
        allow_remote=args.allow_remote,
        allowed_hosts=allowed,
        enable_broker=enable_broker,
        agent_token=agent,
        broker_max_pending=args.broker_max_pending,
        broker_max_ttl_seconds=args.broker_max_ttl_seconds,
        broker_body_max_bytes=args.broker_body_max_bytes,
    )
