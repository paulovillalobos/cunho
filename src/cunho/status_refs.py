"""The status references of wallet and key attestations: an entry in a wallet provider's status list or identifier
list (CIR 2024/2979 Annex II EAA-6.2.10.1-02.2, -02.3), as cunho reads them from an attestation and keeps them for
revocation chaining. Apart from cunho.wallet_status, which fetches the lists, so the modules that only read
references do not depend on fetching."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cunho.jose import JoseError, b64u, b64u_decode

MAX_ID = 64  # bytes of one identifier


class StatusError(JoseError):
    """An attestation whose status is not VALID, or cannot be known. A JoseError, as every refusal of something a
    wallet provider signed is, so the callers handle it where they handle the attestation's other failures."""


class Revoked(StatusError):
    """The wallet provider's list says the attestation is not VALID: known, unlike every other StatusError, which
    leaves the status unknown. Revocation chaining revokes on this one and only alerts on the others."""


@dataclass(frozen=True)
class Reference:
    """One entry an attestation's status names: an index in a status list, or an identifier that a revocation lists
    in an identifier list (CIR 2024/2979 Annex II EAA-6.2.10.1-02.2, -02.3)."""

    uri: str
    idx: int | None = None
    id: bytes | None = None

    def member(self) -> dict[str, Any]:
        """The reference as an attestation's status member carries it, to keep and read back."""
        if self.id is not None:
            return {"identifier_list": {"id": b64u(self.id), "uri": self.uri}}
        return {"status_list": {"idx": self.idx, "uri": self.uri}}


def references(status: Any) -> list[Reference]:
    """The entries a `{"status": {...}}` member names, as both attestations carry it: a `status_list` with `uri` and
    `idx`, an `identifier_list` with `uri` and `id` (the identifier's bytes as base64url, as JSON carries them), or
    both. A member that names neither, or one malformed, names nothing usable."""
    inner = status.get("status") if isinstance(status, dict) else None
    if not isinstance(inner, dict):
        raise StatusError("the attestation names no status list or identifier list entry")
    found: list[Reference] = []
    if "status_list" in inner:
        listed = inner["status_list"]
        uri = listed.get("uri") if isinstance(listed, dict) else None
        idx = listed.get("idx") if isinstance(listed, dict) else None
        if not isinstance(uri, str) or not isinstance(idx, int) or isinstance(idx, bool) or idx < 0:
            raise StatusError("the attestation's status list entry is malformed")
        found.append(Reference(uri, idx=idx))
    if "identifier_list" in inner:
        listed = inner["identifier_list"]
        uri = listed.get("uri") if isinstance(listed, dict) else None
        try:
            ident = b64u_decode(listed.get("id") if isinstance(listed, dict) else None)
        except JoseError:
            ident = b""
        if not isinstance(uri, str) or not 0 < len(ident) <= MAX_ID:
            raise StatusError("the attestation's identifier list entry is malformed")
        found.append(Reference(uri, id=ident))
    if not found:
        raise StatusError("the attestation names no status list or identifier list entry")
    return found
