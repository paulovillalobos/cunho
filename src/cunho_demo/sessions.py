"""Visitors' demo sessions, in memory only: what each QR code on a page stands for, for half an hour.

A session holds no personal data: the persona is fictional, and the subject reference is cunho's pseudonymous
reference of the offer. Losing them on a restart only ends the demos under way."""

from __future__ import annotations

import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from cunho.keyring import same
from cunho_demo.wallet import Activity, offer_token


@dataclass
class Session:
    credential: str  # "pid" or "course"
    format: str  # "both" for the PID, "sd_jwt" or "mdoc" for the course certificate
    flow: str  # "pre-authorized_code" or "authorization_code"
    persona: str
    configurations: list[str]
    expires: float = 0.0  # the session's end, by the sessions' clock; set when it is added
    offer_expires: float = 0.0  # when a wallet can no longer start from the offer, by the same clock
    id: str = field(default_factory=lambda: secrets.token_urlsafe(16))
    subject_ref: str | None = None  # cunho's reference, once there is a subject (at once, or after the login)
    offer_ref: str | None = None  # a code-flow offer's reference, which the login names
    signing_in: bool = False  # the wallet's browser reached the login screen
    cancelled: bool = False  # the person cancelled on the login or consent screen
    revoked: bool = False
    offer: dict[str, Any] | None = None  # the credential offer, served by reference at /offers/{token}
    tx_code: str | None = None  # the offer's PIN, which the page shows and the demo wallet types
    # The offer's reference: what a wallet fetches it by and what the phone page is opened with. It is in the QR
    # code, so it gives less than the session id: the offer, the progress, the demo wallet, never the PIN.
    token: str = field(default_factory=offer_token)
    wallet: Activity | None = None  # the demo wallet's run, once the visitor starts it
    client: str = ""  # the network that made it (cunho.app.client_bucket), for the bound on what one network holds
    progress: dict[str, Any] | None = None  # what the issuer last said of the subject, for when it is not asked again


class Sessions:
    """A bounded table: when it is full, a new session is refused rather than another visitor's dropped, so a
    burst of new visitors never breaks a demo under way. A session is added before its offer is made at cunho, so
    the bound holds for the work sent to cunho too, and removed again when the offer fails. Every session lives the
    same time from the moment it is added, under the lock, so the table's order is the order they end in.

    One client network holds at most `per_client` sessions: its own oldest gives way to its new one. Without that
    bound a handful of networks, each within its rate limit, could hold every place for as long as a session lives
    and have every other visitor told the demo is busy (the security review)."""

    def __init__(
        self,
        ttl: int,
        max_sessions: int,
        offer_ttl: int,
        clock: Callable[[], float] = time.monotonic,
        per_client: int | None = None,
    ) -> None:
        self.ttl = ttl
        self.offer_ttl = offer_ttl
        self._max = max_sessions
        self._per_client = per_client
        self.clock = clock
        self._sessions: OrderedDict[str, Session] = OrderedDict()
        self._lock = threading.Lock()

    def _purge(self) -> None:
        now = self.clock()
        while self._sessions:
            first = next(iter(self._sessions.values()))
            if first.expires > now:
                break
            self._sessions.popitem(last=False)

    def add(self, session: Session) -> bool:
        with self._lock:
            self._purge()
            if self._per_client is not None:
                held = [s.id for s in self._sessions.values() if s.client == session.client]
                for oldest in held[: max(0, len(held) - self._per_client + 1)]:
                    del self._sessions[oldest]
            if len(self._sessions) >= self._max:
                return False
            now = self.clock()
            session.expires, session.offer_expires = now + self.ttl, now + self.offer_ttl
            self._sessions[session.id] = session
            return True

    def remove(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)

    def get(self, session_id: str) -> Session | None:
        with self._lock:
            self._purge()
            return self._sessions.get(session_id)

    def recent(self, count: int) -> list[Session]:
        """The newest sessions first, for the operator console."""
        with self._lock:
            self._purge()
            return list(reversed(self._sessions.values()))[:count]

    def with_subject(self, subject_ref: str) -> list[Session]:
        with self._lock:
            self._purge()
            return [s for s in self._sessions.values() if s.subject_ref == subject_ref]

    def by_offer(self, offer_ref: str) -> Session | None:
        with self._lock:
            self._purge()
            return next((s for s in self._sessions.values() if s.offer_ref == offer_ref), None)

    def by_token(self, token: str) -> Session | None:
        with self._lock:
            self._purge()
            # Compared as bytes: a reference from a URL may hold any text, and the comparison of str refuses
            # text that is not ASCII by raising (the security review).
            return next((s for s in self._sessions.values() if same(s.token, token)), None)

    def __len__(self) -> int:
        with self._lock:
            self._purge()
            return len(self._sessions)
