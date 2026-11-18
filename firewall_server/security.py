"""Authentication, rate limiting, safe logging and common HTTP protections."""
from __future__ import annotations

import hmac
import logging
import time
import uuid
from collections import defaultdict, deque

from fastapi import HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from firewall_server.settings import Settings

bearer = HTTPBearer(auto_error=False)


class FailureThrottle:
    def __init__(self, clock=time.monotonic, limit=5, window=60.0, cooldown=60.0):
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


def generic_error(status: int, code: str):
    raise HTTPException(status_code=status, detail={"error": "Request could not be completed.", "code": code})


def role_dependency(settings: Settings, throttle: FailureThrottle):
    async def require(request: Request, credentials: HTTPAuthorizationCredentials | None = None) -> str:
        ip = request.client.host if request.client else "unknown"
        if throttle.blocked(ip):
            generic_error(429, "AUTH_THROTTLED")
        token = credentials.credentials if credentials else ""
        if hmac.compare_digest(token, settings.reviewer_token):
            return "reviewer"
        if hmac.compare_digest(token, settings.viewer_token):
            return "viewer"
        throttle.failure(ip)
        generic_error(401, "UNAUTHORIZED")
    return require


class TokenRedactionFilter(logging.Filter):
    def __init__(self, tokens: tuple[str, ...]):
        super().__init__(); self.tokens = tuple(token for token in tokens if token)
    def filter(self, record):
        message = record.getMessage()
        for token in self.tokens:
            message = message.replace(token, "[REDACTED]")
        record.msg, record.args = message, ()
        return True


def request_id() -> str:
    return uuid.uuid4().hex
