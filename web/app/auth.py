"""Single-user login (spec section 5): argon2id password check, in-memory sessions, login lockout, check rate limit.

All state lives in this process's memory: a restart logs everyone out and clears lockouts. Not safe to share
between processes or threads that run separate event loops; the app runs one uvicorn worker with one event loop
(the same assumption as the busy counter in main.py).
"""

from __future__ import annotations

import hashlib
import secrets
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

SESSION_COOKIE = "certcheck_session"
MAX_SESSIONS = 32  # one user; the oldest session is dropped beyond this
MAX_PASSWORD = 1024  # longer submissions are refused before hashing (argon2 cost is per byte too)
GLOBAL_FACTOR = 4  # all addresses together get this many times the per-address failure allowance

Clock = Callable[[], float]
_hasher = PasswordHasher()  # argon2-cffi defaults: argon2id, RFC 9106 low-memory profile


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored: str, password: str) -> bool:
    """Constant work per attempt (argon2 verify); a malformed stored hash fails closed."""
    if not password or len(password) > MAX_PASSWORD:
        return False
    try:
        return _hasher.verify(stored, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


@dataclass
class _Session:
    created: float
    seen: float


class Sessions:
    """Opaque random session ids (256 bits). Only a SHA-256 of each id is kept, so the table holds nothing a
    cookie could be rebuilt from. Idle and absolute lifetimes both apply."""

    def __init__(self, idle_s: int, max_s: int, clock: Clock = time.monotonic) -> None:
        self.idle_s, self.max_s, self.clock = idle_s, max_s, clock
        self._s: dict[str, _Session] = {}

    @staticmethod
    def _key(sid: str) -> str:
        return hashlib.sha256(sid.encode()).hexdigest()

    def create(self) -> str:
        now = self.clock()
        self._purge(now)
        while len(self._s) >= MAX_SESSIONS:
            del self._s[min(self._s, key=lambda k: self._s[k].created)]
        sid = secrets.token_urlsafe(32)
        self._s[self._key(sid)] = _Session(now, now)
        return sid

    def valid(self, sid: str | None) -> bool:
        if not sid or len(sid) > 64:
            return False
        now = self.clock()
        s = self._s.get(self._key(sid))
        if s is None:
            return False
        if now - s.seen > self.idle_s or now - s.created > self.max_s:
            del self._s[self._key(sid)]
            return False
        s.seen = now
        return True

    def drop(self, sid: str | None) -> None:
        if sid:
            self._s.pop(self._key(sid), None)

    def _purge(self, now: float) -> None:
        for k in [k for k, s in self._s.items() if now - s.seen > self.idle_s or now - s.created > self.max_s]:
            del self._s[k]

    def __len__(self) -> int:
        return len(self._s)


class Lockout:
    """failures failed logins from one address inside window_s lock that address out for lockout_s. All addresses
    together get GLOBAL_FACTOR times that allowance before every login is locked, so spreading guesses over many
    LAN addresses gains little. A successful login clears that address's count (not the global one)."""

    def __init__(self, failures: int, window_s: int, lockout_s: int, clock: Clock = time.monotonic) -> None:
        self.failures, self.window_s, self.lockout_s, self.clock = failures, window_s, lockout_s, clock
        self._fails: dict[str, deque[float]] = {}
        self._until: dict[str, float] = {}

    def retry_after(self, addr: str) -> int:
        """Seconds until a login from addr may be tried; 0 means now."""
        now = self.clock()
        left = max(self._until.get(addr, 0.0), self._until.get("*", 0.0)) - now
        return max(0, int(left + 0.999))

    def fail(self, addr: str) -> None:
        now = self.clock()
        for key, limit in ((addr, self.failures), ("*", self.failures * GLOBAL_FACTOR)):
            q = self._fails.setdefault(key, deque())
            q.append(now)
            while q and now - q[0] > self.window_s:
                q.popleft()
            if len(q) >= limit:
                self._until[key] = now + self.lockout_s
                q.clear()
        if len(self._fails) > 4096:  # bounded memory: forget the quietest addresses
            for k in sorted(self._fails, key=lambda k: self._fails[k][-1] if self._fails[k] else 0)[:2048]:
                if k != "*":
                    del self._fails[k]
        for k in [k for k, t in self._until.items() if t <= now]:
            del self._until[k]

    def success(self, addr: str) -> None:
        self._fails.pop(addr, None)


class RateLimit:
    """At most per_minute checks per client address in any 60 s window (sliding log)."""

    def __init__(self, per_minute: int, clock: Clock = time.monotonic) -> None:
        self.per_minute, self.clock = per_minute, clock
        self._log: dict[str, deque[float]] = {}

    def take(self, addr: str) -> int:
        """Record one check and return 0, or return the seconds to wait (nothing recorded)."""
        now = self.clock()
        q = self._log.setdefault(addr, deque())
        while q and now - q[0] >= 60:
            q.popleft()
        if len(q) >= self.per_minute:
            return max(1, int(60 - (now - q[0]) + 0.999))
        q.append(now)
        if len(self._log) > 4096:
            for k in [k for k, v in self._log.items() if not v or now - v[-1] >= 60]:
                del self._log[k]
        return 0
