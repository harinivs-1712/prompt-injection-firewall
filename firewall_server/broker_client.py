"""Host-side client callback that sends ASK decisions to the approval broker."""
from __future__ import annotations

import logging
import time
from urllib.parse import urlparse
from typing import Any

import httpx

from firewall.api import Firewall
from firewall.approval import ReviewPacket

logger = logging.getLogger("firewall_server.broker_client")

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}


class BrokerApprovalCallback:
    """Synchronous ApprovalCallback connecting the agent process to the approval broker."""

    def __init__(
        self,
        base_url: str,
        agent_token: str,
        poll_wait: float = 15.0,
        request_timeout: float = 5.0,
        allow_remote: bool = False,
    ):
        self.base_url = base_url.rstrip("/")
        self.agent_token = agent_token
        self.poll_wait = float(poll_wait)
        self.request_timeout = float(request_timeout)
        self.allow_remote = bool(allow_remote)

        parsed = urlparse(self.base_url)
        hostname = parsed.hostname or ""
        if hostname not in LOOPBACK_HOSTS and not self.allow_remote:
            raise ValueError(f"Refusing non-loopback base_url '{self.base_url}' without allow_remote=True")
        if self.allow_remote and hostname not in LOOPBACK_HOSTS:
            logger.warning("Remote broker connection configured: TLS and a reverse proxy are required.")

    def __repr__(self) -> str:
        return (
            f"BrokerApprovalCallback(base_url={self.base_url!r}, agent_token='<redacted>', "
            f"poll_wait={self.poll_wait}, request_timeout={self.request_timeout}, allow_remote={self.allow_remote})"
        )

    def __call__(self, packet: ReviewPacket, timeout_seconds: float) -> bool:
        start_time = time.monotonic()
        req_id: str | None = None

        headers = {
            "Authorization": f"Bearer {self.agent_token}",
            "Content-Type": "application/json",
        }

        body = {
            "session_id": str(packet.session_id),
            "tool": str(packet.tool),
            "reason_codes": [str(c.value if hasattr(c, "value") else c) for c in (packet.reason_codes or ())],
            "explanation": str(packet.explanation or ""),
            "evidence_summary": list(packet.link_evidence or ()),
            "sensitivity_flags": [str(f) for f in (packet.sensitivity_flags or ())],
            "values_preview": dict(packet.values_preview or {}),
            "ttl_seconds": float(timeout_seconds),
        }

        try:
            with httpx.Client(timeout=self.request_timeout) as client:
                resp = client.post(
                    f"{self.base_url}/api/v1/broker/requests",
                    headers=headers,
                    json=body,
                )
                if resp.status_code not in {200, 201}:
                    return False

                data = resp.json()
                req_id = data.get("request_id")
                if not req_id:
                    return False

                while time.monotonic() - start_time < timeout_seconds:
                    elapsed = time.monotonic() - start_time
                    remaining = timeout_seconds - elapsed
                    if remaining <= 0:
                        break

                    wait_secs = max(0.5, min(self.poll_wait, remaining))
                    poll_resp = client.get(
                        f"{self.base_url}/api/v1/broker/requests/{req_id}/decision",
                        headers=headers,
                        params={"wait_seconds": wait_secs},
                        timeout=wait_secs + self.request_timeout,
                    )
                    if poll_resp.status_code != 200:
                        return False

                    poll_data = poll_resp.json()
                    status = poll_data.get("status")
                    if status == "approved":
                        return True
                    if status in {"denied", "expired", "cancelled"}:
                        return False

            # Timeout elapsed without a terminal status
            if req_id:
                try:
                    with httpx.Client(timeout=self.request_timeout) as cancel_client:
                        cancel_client.post(
                            f"{self.base_url}/api/v1/broker/requests/{req_id}/cancel",
                            headers=headers,
                        )
                except Exception:
                    pass
            return False

        except Exception:
            return False


def make_firewall_with_broker(
    policy: Any,
    base_url: str,
    agent_token: str,
    *,
    poll_wait: float = 15.0,
    request_timeout: float = 5.0,
    allow_remote: bool = False,
    **kwargs: Any,
) -> Firewall:
    """Helper creating a Firewall instance wired with a BrokerApprovalCallback."""
    callback = BrokerApprovalCallback(
        base_url=base_url,
        agent_token=agent_token,
        poll_wait=poll_wait,
        request_timeout=request_timeout,
        allow_remote=allow_remote,
    )
    return Firewall(policy=policy, approval_callback=callback, **kwargs)
