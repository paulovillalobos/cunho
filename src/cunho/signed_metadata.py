"""Signed issuer metadata (VCI.META.SIGNED_FORMAT, META.SIGNED_X5C_ACCESS_CERT; OpenID4VCI 1.0 §12.2.3, HAIP 1.0 §4.1,
ETSI TS 119 472-3 V1.1.1 §4.2.1, §4.2.2, ARF ISSU_22).

The metadata is always served as JSON. A client that asks for `application/jwt` gets the same document as the payload
of a JWT of type `openidvci-issuer-metadata+jwt`, with `sub` the issuer identifier, `iat` and a short `exp`, signed by
the issuer's access certificate, whose path up to but excluding its trust anchor is in `x5c`. The access certificate
signs nothing else: it is not self-signed, and its key is neither the credential signer's nor the status list
signer's, so each key keeps one purpose.
"""

from __future__ import annotations

import base64
from typing import Any

from cryptography import x509

from cunho.errors import ConfigError
from cunho.jose import is_self_signed, thumbprint
from cunho.rules import implements
from cunho.signer import Signer, sign_jws

METADATA_TYP = "openidvci-issuer-metadata+jwt"


def check_access_signer(access: Signer, credentials: Signer, status: Signer) -> None:
    """Startup checks of the signer of the metadata. Raises ConfigError."""
    try:
        leaf = x509.load_der_x509_certificate(access.certificate_der())
        sent = [x509.load_der_x509_certificate(base64.b64decode(c)) for c in access.x5c()]
    except ValueError as exc:
        raise ConfigError("the access certificate cannot be read") from exc
    if is_self_signed(leaf):
        raise ConfigError("the access certificate is self-signed; HAIP 1.0 §4.1 asks for one under an access CA")
    if not sent or sent[0] != leaf or any(is_self_signed(c) for c in sent):
        raise ConfigError("the access signer's x5c must start with its certificate and leave out the trust anchor")
    own = thumbprint(access.public_jwk())
    if own in {thumbprint(credentials.public_jwk()), thumbprint(status.public_jwk())}:
        raise ConfigError("the access certificate's key must not be the credential or status list signing key")


@implements("VCI.META.SIGNED_FORMAT", "META.SIGNED_X5C_ACCESS_CERT")
def signed_metadata(document: dict[str, Any], access: Signer, now: int, ttl: int) -> str:
    """The metadata as a signed JWT: the document, the issuer identifier as `sub`, `iat` now and `exp` `ttl` later."""
    payload = {**document, "sub": document["credential_issuer"], "iat": now, "exp": now + ttl}
    return sign_jws(access, {"typ": METADATA_TYP, "x5c": access.x5c()}, payload)


def wants_jwt(accept: str | None) -> bool:
    """Whether an Accept header prefers `application/jwt` to JSON (RFC 9110 §12.5.1). Each form takes the weight of
    the most specific range that matches it (the type itself, then `application/*`, then `*/*`), so an explicit
    q=0 is not undone by a wildcard; JSON, the form that must always be there, is the default and wins a tie."""
    if not accept:
        return False
    weights: dict[str, float] = {}
    for part in accept.split(","):
        fields = [f.strip() for f in part.split(";")]
        kind, quality = fields[0].lower(), 1.0
        for field in fields[1:]:
            name, _, value = field.partition("=")
            if name.strip().lower() == "q":
                try:
                    quality = float(value)
                except ValueError:
                    quality = 0.0
        if kind in ("application/jwt", "application/json", "application/*", "*/*"):
            weights[kind] = max(weights.get(kind, 0.0), quality)

    def weight(kind: str) -> float:
        for name in (kind, "application/*", "*/*"):
            if name in weights:
                return weights[name]
        return 0.0

    jwt, json_ = weight("application/jwt"), weight("application/json")
    return jwt > 0 and jwt > json_
