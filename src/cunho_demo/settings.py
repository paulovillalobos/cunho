"""The demo service's settings, from DEMO_* environment variables."""

from __future__ import annotations

import ipaddress
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

PERSONAS = Path(__file__).with_name("personas.json")
# The PID in both formats, as a PID provider must offer it (ARF PID_02); a PID provider without an mdoc document
# signer publishes the SD-JWT VC alone, and DEMO_PID_CONFIGURATIONS says so.
PID_CONFIGURATIONS = ("eu.europa.ec.eudi.pid_vc_sd_jwt", "eu.europa.ec.eudi.pid_mdoc")


class DemoConfigError(Exception):
    """A setting the demo refuses to start with."""


@dataclass(frozen=True)
class IssuerLink:
    """Where the demo reaches one cunho's admin API, the operator token it uses there, and, for an https URL
    whose certificate is not from a public CA (a development one), the PEM file of the CA to trust instead."""

    url: str
    token: str
    ca_file: Path | None = None


@dataclass(frozen=True)
class DemoSettings:
    public_url: str  # the origin visitors' browsers are on; POSTs from any other origin are refused
    pid: IssuerLink  # the PID provider
    course: IssuerLink  # the attestation provider that issues the course certificate
    personas: Path = PERSONAS
    session_ttl: int = 1800  # a visitor's demo session, in memory only
    offer_ttl: int = 600  # cunho's CUNHO_OFFER_TTL, so a code-flow offer can be called expired before any login
    login_ttl: int = 600  # cunho's CUNHO_LOGIN_TTL: how long a login opened on the screens can still be reported
    max_sessions: int = 2000  # live sessions at once; past that a new one is refused, never an old one dropped
    # A client network is an IPv4 address or an IPv6 /56, the smallest block a home connection is usually given.
    sessions_per_minute: int = 12  # new sessions per client network
    sessions_per_client: int = 40  # live sessions one client network holds; its oldest gives way to a new one
    polls_per_minute: int = 240  # progress reads and actions per client network
    logins_per_minute: int = 60  # requests to the login and consent screens per client network
    # Progress reads sent to one issuer in a minute, for all visitors together: kept under what the issuer allows
    # the operator token (CUNHO_OPERATOR_RATE_LIMIT_PER_MINUTE, 6000 by default), so the visitors' polling can
    # never use up what offers, logins and the console need. Past it a poll is answered with what was read last.
    progress_per_minute: int = 3000
    pid_validity_days: int = 30  # a demo PID's date_of_expiry, from the day it is offered
    secret_key: bytes = b""  # signs the login screens' cookies; 32 random bytes in a file, chmod 600
    pid_configurations: tuple[str, ...] = PID_CONFIGURATIONS
    operator_password_hash: str | None = None  # the console's password as scrypt (python -m cunho_demo.console)
    # Other origins the same service is reached from, whose forms and JSON it takes too: a second name for it, or
    # tools/demo_local.py's plain-http view. Each an origin, as public_url is.
    extra_origins: tuple[str, ...] = ()
    # The demo wallet's key-attestation signer, a wallet provider's the issuers trust: its certificate chain (the
    # signer first) and its key. Without them the page offers no demo wallet.
    wallet_ka_chain: Path | None = None
    wallet_ka_key: Path | None = None

    def __post_init__(self) -> None:
        checked = [("DEMO_PUBLIC_URL", self.public_url)] + [("DEMO_EXTRA_ORIGINS", o) for o in self.extra_origins]
        for name, url in checked:
            parts = urlsplit(url)
            if parts.scheme != "https" and not (parts.scheme == "http" and _local(parts.hostname)):
                raise DemoConfigError(f"{name} must be https (http only for this machine or a private network)")
            if parts.path not in ("", "/") or parts.query or parts.fragment or not parts.hostname:
                raise DemoConfigError(f"{name} is an origin: scheme, host and port only")
        if (self.wallet_ka_chain is None) != (self.wallet_ka_key is None):
            raise DemoConfigError("the demo wallet needs both DEMO_WALLET_KA_CHAIN_FILE and DEMO_WALLET_KA_KEY_FILE")
        if self.wallet_ka_key is not None:
            _private(self.wallet_ka_key)
        for name, link in (("PID", self.pid), ("COURSE", self.course)):
            if urlsplit(link.url).scheme not in ("http", "https"):
                raise DemoConfigError(f"DEMO_{name}_ADMIN_URL must be an http(s) URL")
            if len(link.token) < 32:
                raise DemoConfigError(f"the {name} operator token is too short")
        if len(self.secret_key) < 32:
            raise DemoConfigError("DEMO_SECRET_KEY_FILE must hold at least 32 bytes")
        for name in (
            "session_ttl",
            "offer_ttl",
            "login_ttl",
            "max_sessions",
            "sessions_per_minute",
            "sessions_per_client",
            "polls_per_minute",
            "logins_per_minute",
            "progress_per_minute",
        ):
            if getattr(self, name) <= 0:
                raise DemoConfigError(f"{name} must be positive")
        if self.operator_password_hash is not None and not self.operator_password_hash.startswith("scrypt$"):
            raise DemoConfigError("DEMO_OPERATOR_PASSWORD_FILE must hold a hash from python -m cunho_demo.console")
        if not self.pid_configurations:
            raise DemoConfigError("DEMO_PID_CONFIGURATIONS names at least one configuration")
        if not 1 <= self.pid_validity_days <= 365:
            raise DemoConfigError("pid_validity_days must be from 1 to 365")

    @property
    def origin(self) -> str:
        parts = urlsplit(self.public_url)
        return f"{parts.scheme}://{parts.netloc}"

    @property
    def origins(self) -> frozenset[str]:
        """Every origin whose forms and JSON the service takes."""
        extra = {f"{urlsplit(o).scheme}://{urlsplit(o).netloc}" for o in self.extra_origins}
        return frozenset({self.origin} | extra)

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ) -> DemoSettings:
        def required(name: str) -> str:
            value = env.get(name)
            if not value:
                raise DemoConfigError(f"{name} is required")
            return value

        ca = env.get("DEMO_ISSUER_CA_FILE")
        ca_file = Path(ca) if ca else None
        if ca_file is not None and not ca_file.is_file():
            raise DemoConfigError(f"DEMO_ISSUER_CA_FILE: no file at {ca_file}")

        def number(name: str, default: int) -> int:
            value = env.get(name)
            if value is None:
                return default
            try:
                return int(value)
            except ValueError:
                raise DemoConfigError(f"{name} must be a whole number") from None

        return cls(
            public_url=required("DEMO_PUBLIC_URL"),
            pid=IssuerLink(
                required("DEMO_PID_ADMIN_URL"), secret_text(Path(required("DEMO_PID_ADMIN_TOKEN_FILE"))), ca_file
            ),
            course=IssuerLink(
                required("DEMO_COURSE_ADMIN_URL"), secret_text(Path(required("DEMO_COURSE_ADMIN_TOKEN_FILE"))), ca_file
            ),
            personas=Path(env.get("DEMO_PERSONAS") or PERSONAS),
            session_ttl=number("DEMO_SESSION_TTL", 1800),
            offer_ttl=number("DEMO_OFFER_TTL", 600),
            login_ttl=number("DEMO_LOGIN_TTL", 600),
            max_sessions=number("DEMO_MAX_SESSIONS", 2000),
            sessions_per_minute=number("DEMO_SESSIONS_PER_MINUTE", 12),
            sessions_per_client=number("DEMO_SESSIONS_PER_CLIENT", 40),
            polls_per_minute=number("DEMO_POLLS_PER_MINUTE", 240),
            logins_per_minute=number("DEMO_LOGINS_PER_MINUTE", 60),
            progress_per_minute=number("DEMO_PROGRESS_PER_MINUTE", 3000),
            pid_validity_days=number("DEMO_PID_VALIDITY_DAYS", 30),
            secret_key=secret_bytes(Path(required("DEMO_SECRET_KEY_FILE"))),
            extra_origins=tuple(o.strip() for o in (env.get("DEMO_EXTRA_ORIGINS") or "").split(",") if o.strip()),
            operator_password_hash=secret_text(Path(password))
            if (password := env.get("DEMO_OPERATOR_PASSWORD_FILE"))
            else None,
            wallet_ka_chain=Path(chain) if (chain := env.get("DEMO_WALLET_KA_CHAIN_FILE")) else None,
            wallet_ka_key=Path(key) if (key := env.get("DEMO_WALLET_KA_KEY_FILE")) else None,
            pid_configurations=tuple(
                c.strip() for c in (env.get("DEMO_PID_CONFIGURATIONS") or ",".join(PID_CONFIGURATIONS)).split(",")
            ),
        )


def _local(host: str | None) -> bool:
    """This machine, or an address on a private network (a phone on the same Wi-Fi reaching a local run): the only
    places the demo may be served over plain http."""
    if host == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host or "")
    except ValueError:
        return False
    return address.is_loopback or address.is_private


def _private(path: Path) -> None:
    try:
        mode = path.stat().st_mode
    except OSError as exc:
        raise DemoConfigError(f"cannot read {path}: {exc.strerror}") from None
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise DemoConfigError(f"{path} must be readable by the demo's user only (chmod 600)")


def secret_text(path: Path) -> str:
    _private(path)
    return path.read_text().strip()


def secret_bytes(path: Path) -> bytes:
    _private(path)
    return path.read_bytes()
