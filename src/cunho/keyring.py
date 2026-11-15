"""Secrets that must live outside the data store.

One master secret, read from a file the operator keeps apart from the database and its backups,
yields every symmetric key cunho needs: the vault key-encryption key, the audit-log MAC key, the
DPoP nonce key and the key that hashes transaction codes. Stealing the database alone therefore
reveals no personal data, cannot forge the audit chain and cannot reverse a stored tx_code.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path

from cunho.errors import ConfigError

MASTER_BYTES = 32


class Keyring:
    def __init__(self, master: bytes) -> None:
        if len(master) < MASTER_BYTES:
            raise ConfigError(f"the master secret must be at least {MASTER_BYTES} bytes")
        self._master = master

    @classmethod
    def ephemeral(cls) -> Keyring:
        """For tests and in-memory development runs: lost when the process exits."""
        return cls(secrets.token_bytes(MASTER_BYTES))

    @classmethod
    def from_file(cls, path: Path, *, create: bool) -> Keyring:
        if not path.exists():
            if not create:
                raise ConfigError(f"secret key file {path} does not exist")
            cls._create(path)
        if path.stat().st_mode & 0o077:
            raise ConfigError(f"secret key file {path} must not be readable by group or others (chmod 600)")
        return cls(path.read_bytes())

    @staticmethod
    def _create(path: Path) -> None:
        """Write the secret to a private temporary file, then link it into place.

        Several worker processes start at once and may all find the file missing. The link either
        creates the complete file or fails because another worker already did, so no worker ever reads
        a half-written secret and they all end up with the same one.
        """
        temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(secrets.token_bytes(MASTER_BYTES))
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temporary, path)
            except FileExistsError:
                pass
        finally:
            temporary.unlink(missing_ok=True)

    def derive(self, purpose: str) -> bytes:
        return hmac.new(self._master, f"cunho/{purpose}/v1".encode(), hashlib.sha256).digest()

    def mac(self, purpose: str, data: bytes | str) -> str:
        message = data.encode() if isinstance(data, str) else data
        return hmac.new(self.derive(purpose), message, hashlib.sha256).hexdigest()


def same(left: str | bytes, right: str | bytes) -> bool:
    """Constant-time comparison that never raises on non-ASCII input."""
    a = left.encode("utf-8", "surrogatepass") if isinstance(left, str) else left
    b = right.encode("utf-8", "surrogatepass") if isinstance(right, str) else right
    return hmac.compare_digest(a, b)
