"""Authentication, rate limiting, safe logging and common HTTP protections."""
from __future__ import annotations

import hmac
import logging
import time
import uuid
from collections import defaultdict, deque
from typing import Callable

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from firewall_server.settings import Settings

bearer = HTTPBearer(auto_error=False)


class FailureThrottle:
    def __init__(self, clock: Callable[[], float] = time.monotonic, limit: int = 5, window: float = 60.0, cooldown: float = 60.0):
        self.clock, self.limit, self.window, self.cooldown = clock, limit, window, cooldown
        self.failures: dict[str, deque[float]] = defaultdict(deque)
        self.blocked_until: dict[str, float] = {}

    def blocked(self, ip: str) -> bool:
        return self.blocked_until.get(ip, 0) > self.clock()

    def failure(self, ip: str) -> None:
        now, history = self.clock(), self.failures[ip]
        while history and history[0] <= now - self.window:
            history.popleft()
        history.append(now)
        if len(history) > self.limit:
            self.blocked_until[ip] = now + self.cooldown


class ActionRateLimiter:
    """Sliding-window rate limiter for specific actions (creates/decisions)."""
    def __init__(self, clock: Callable[[], float] = time.monotonic, limit: int = 120, window: float = 60.0):
        self.clock, self.limit, self.window = clock, limit, window
        self.calls: dict[str, deque[float]] = defaultdict(deque)

    def is_allowed(self, key: str) -> bool:
        now = self.clock()
        history = self.calls[key]
        while history and history[0] <= now - self.window:
            history.popleft()
        if len(history) >= self.limit:
            return False
        history.append(now)
        return True

    def check(self, key: str, action: str = "request") -> None:
        if not self.is_allowed(f"{action}:{key}"):
            generic_error(429, "RATE_LIMITED", "Action rate limit exceeded.")


def generic_error(status: int, code: str, message: str = "Request could not be completed."):
    raise HTTPException(status_code=status, detail={"error": message, "code": code})


def get_token_role(token: str, settings: Settings) -> str | None:
    if not token:
        return None
    if settings.reviewer_token and hmac.compare_digest(token, settings.reviewer_token):
        return "reviewer"
    if settings.viewer_token and hmac.compare_digest(token, settings.viewer_token):
        return "viewer"
    if settings.enable_broker and settings.agent_token and hmac.compare_digest(token, settings.agent_token):
        return "agent"
    return None


def auth_guard(settings: Settings, throttle: FailureThrottle, allowed_roles: set[str]):
    async def dependency(request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> str:
        ip = request.client.host if request.client else "unknown"
        if throttle.blocked(ip):
            generic_error(429, "AUTH_THROTTLED")

        token = credentials.credentials if credentials else ""
        role = get_token_role(token, settings)
        if role is None:
            throttle.failure(ip)
            generic_error(401, "UNAUTHORIZED")

        if role not in allowed_roles:
            generic_error(403, "FORBIDDEN")
        return role

    return dependency


def role_dependency(settings: Settings, throttle: FailureThrottle, allowed_roles: set[str] | None = None):
    allowed = allowed_roles or {"viewer", "reviewer"}
    return auth_guard(settings, throttle, allowed)


class TokenRedactionFilter(logging.Filter):
    def __init__(self, tokens: tuple[str, ...]):
        super().__init__()
        self.tokens = tuple(token for token in tokens if token and len(token) >= 8)

    def filter(self, record):
        message = record.getMessage()
        for token in self.tokens:
            message = message.replace(token, "[REDACTED]")
        record.msg, record.args = message, ()
        return True


def request_id() -> str:
    return uuid.uuid4().hex
