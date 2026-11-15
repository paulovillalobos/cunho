import json
from pathlib import Path
from urllib.parse import quote

import pytest

from eudi_probe.checks import FAIL, PASS, REGISTRY, WARN, expect_rejected
from eudi_probe.context import Context, Exchange, ProbeConfig, append_well_known, insert_well_known
from eudi_probe.jose import (
    EcKey,
    b64u,
    b64u_decode,
    jwk_thumbprint,
    parse_jws,
    sha256_b64u,
    verify_with_public_key,
)
from eudi_probe.ledger import build, evidence_hash
from eudi_probe.wallet import dpop_proof, fresh_secret, key_proof


def test_b64u_round_trip() -> None:
    for data in (b"", b"\x00", b"\xff\xfe\xfd", bytes(range(64))):
        assert b64u_decode(b64u(data)) == data
        assert "=" not in b64u(data)


def test_es256_sign_and_verify() -> None:
    key = EcKey.generate()
    token = key_proof(key, "https://issuer.example", nonce="n")
    parsed = parse_jws(token)
    public = key.private.public_key()
    assert verify_with_public_key("ES256", public, parsed.signing_input, parsed.signature)
    assert not verify_with_public_key(
        "ES256", EcKey.generate().private.public_key(), parsed.signing_input, parsed.signature
    )


def test_thumbprint_ignores_member_order_and_private_part() -> None:
    key = EcKey.generate()
    shuffled = dict(reversed(list(key.public_jwk().items())))
    assert jwk_thumbprint(shuffled) == key.thumbprint()
    assert jwk_thumbprint(key.private_jwk()) == key.thumbprint()


def test_private_jwk_round_trip() -> None:
    key = EcKey.generate()
    assert EcKey.from_private_jwk(key.private_jwk()).thumbprint() == key.thumbprint()
    with pytest.raises(ValueError):
        EcKey.from_private_jwk(key.public_jwk())


def test_parse_jws_rejects_malformed() -> None:
    for token in ("a.b", "a.b.c.d", f"{b64u(b'[]')}.{b64u(b'{}')}.x"):
        with pytest.raises(ValueError):
            parse_jws(token)


def test_dpop_proof_shape() -> None:
    key = EcKey.generate()
    proof = parse_jws(dpop_proof(key, "POST", "https://as.example/token?x=1#y", access_token="tok", nonce="n1"))
    assert proof.header["typ"] == "dpop+jwt"
    assert proof.header["alg"] == "ES256"
    assert "d" not in proof.header["jwk"]
    assert proof.payload["htu"] == "https://as.example/token"
    assert proof.payload["htm"] == "POST"
    assert proof.payload["ath"] == sha256_b64u("tok")
    assert proof.payload["nonce"] == "n1"
    assert len(proof.payload["jti"]) >= 16


def test_broken_proof_variants() -> None:
    key = EcKey.generate()
    hs = parse_jws(dpop_proof(key, "POST", "https://as.example/token", alg="HS256", hs256_secret=fresh_secret()))
    assert hs.header["alg"] == "HS256"
    no_jti = parse_jws(dpop_proof(key, "POST", "https://as.example/token", drop=("jti",)))
    assert "jti" not in no_jti.payload


def test_key_proof_claims() -> None:
    proof = parse_jws(key_proof(EcKey.generate(), "https://issuer.example", nonce="c"))
    assert proof.header["typ"] == "openid4vci-proof+jwt"
    assert proof.payload["aud"] == "https://issuer.example"
    assert proof.payload["nonce"] == "c"
    assert "iss" not in proof.payload


def test_well_known_paths() -> None:
    assert insert_well_known("https://h.example/tenant/a", "openid-credential-issuer") == (
        "https://h.example/.well-known/openid-credential-issuer/tenant/a"
    )
    assert insert_well_known("https://h.example", "oauth-authorization-server") == (
        "https://h.example/.well-known/oauth-authorization-server"
    )
    assert append_well_known("https://h.example/tenant/", "openid-configuration") == (
        "https://h.example/tenant/.well-known/openid-configuration"
    )


def test_parse_offer_by_value() -> None:
    offer = {
        "credential_issuer": "https://issuer.example",
        "credential_configuration_ids": ["pid"],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {"pre-authorized_code": "abc", "tx_code": {}}
        },
    }
    ctx = Context(ProbeConfig(issuer="https://issuer.example"))
    parsed = ctx.parse_offer("openid-credential-offer://?credential_offer=" + quote(json.dumps(offer)), "1234")
    assert parsed is not None
    assert parsed.pre_authorized_code == "abc"
    assert parsed.tx_code_required
    assert parsed.tx_code_value == "1234"


def exchange(status: int, body: str, headers: dict[str, str] | None = None) -> Exchange:
    return Exchange("POST", "https://x", status, headers or {}, body)


def test_expect_rejected() -> None:
    assert expect_rejected(exchange(500, ""), statuses={400}).status == FAIL
    assert expect_rejected(exchange(200, "{}"), statuses={400}).status == FAIL
    assert (
        expect_rejected(exchange(400, '{"error":"invalid_proof"}'), statuses={400}, errors={"invalid_proof"}).status
        == PASS
    )
    assert expect_rejected(exchange(400, '{"error":"other"}'), statuses={400}, errors={"invalid_proof"}).status == WARN
    assert expect_rejected(exchange(403, '{"error":"invalid_proof"}'), statuses={400}).status == WARN
    challenge = {"www-authenticate": 'DPoP error="invalid_token"'}
    result = expect_rejected(exchange(401, "", challenge), statuses={401}, errors={"invalid_token"}, header_error=True)
    assert result.status == PASS


def test_registry_is_consistent() -> None:
    ids = [c.id for c in REGISTRY]
    assert len(ids) == len(set(ids))
    for check in REGISTRY:
        assert check.source and check.title
        # The code flow's negatives (M3): every attestation check, and the authorization checks that try a bypass.
        bypasses = {f"A{n:02d}" for n in (4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 17, 18, 21)} | {
            f"W{n:02d}" for n in range(1, 11)
        }
        bypasses |= {"D05", "C17", "E04", "E05"}  # M4: deferred, notification and encryption bypasses
        security = check.id.startswith("S") or check.id in {f"T{n:02d}" for n in range(8, 16)} | bypasses
        assert check.sensitive == security, check.id


def write_run(root: Path, results: list[dict[str, object]], causes: list[dict[str, object]]) -> None:
    run = root / "runs" / "x"
    run.mkdir(parents=True)
    (run / "results.json").write_text(json.dumps({"name": "x@1", "results": results}))
    (run / "rootcause.json").write_text(json.dumps(causes))


def test_ledger_verifies_hashes(tmp_path: Path) -> None:
    evidence = ["GET https://x -> 404 not found"]
    result = {
        "id": "M01",
        "status": "FAIL",
        "sensitive": False,
        "source": "s",
        "title": "t",
        "detail": "d",
        "evidence": evidence,
    }
    write_run(tmp_path, [result], [{"check_id": "M01", "evidence_sha256": evidence_hash(evidence)}])
    rows, _ = build(tmp_path / "runs", tmp_path / "missing.csv")
    assert rows[0].hash_verified == "yes"


def test_ledger_flags_mismatch(tmp_path: Path) -> None:
    result = {
        "id": "M01",
        "status": "FAIL",
        "sensitive": False,
        "source": "s",
        "title": "t",
        "detail": "d",
        "evidence": ["real"],
    }
    write_run(tmp_path, [result], [{"check_id": "M01", "evidence_sha256": evidence_hash(["forged"])}])
    rows, _ = build(tmp_path / "runs", tmp_path / "missing.csv")
    assert rows[0].hash_verified == "MISMATCH"


def test_a_wallet_attestation_signer_must_be_p256(tmp_path: Path) -> None:
    """The probe signs attestations with ES256, so another curve is refused when loaded (the second reviewer)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from eudi_probe.attester import WalletProvider

    chain = tmp_path / "chain.pem"
    chain.write_bytes(b"")
    for curve in (ec.SECP384R1(), ec.SECP521R1()):
        key = tmp_path / "key.pem"
        key.write_bytes(
            ec.generate_private_key(curve).private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )
        with pytest.raises(ValueError, match="must be a P-256 key"):
            WalletProvider.from_signer_files(chain, key)


def test_the_token_client_id_goes_into_every_token_form() -> None:
    """A check's own form gets --token-client-id too, unless it sets client_id itself (the second reviewer)."""
    from eudi_probe.context import Offer

    sent: list[dict[str, str]] = []

    class Recorder:
        def request(self, method: str, url: str, **kwargs: object) -> Exchange:
            sent.append(dict(kwargs["data"]))  # type: ignore[call-overload]
            return Exchange(method, url, 400, {}, "{}")

    ctx = Context(ProbeConfig(issuer="https://issuer.example", token_client_id="probe-client"))
    ctx.http = Recorder()  # type: ignore[assignment]
    ctx.__dict__["as_metadata"] = {"token_endpoint": "https://issuer.example/token"}
    offer = Offer("", [], "code", None, None, {})
    ctx.token_request(offer, EcKey.generate())
    ctx.token_request(offer, EcKey.generate(), form={"grant_type": "x"})
    ctx.token_request(offer, EcKey.generate(), form={"grant_type": "x", "client_id": "own"})
    assert [f.get("client_id") for f in sent] == ["probe-client", "probe-client", "own"]


def test_the_untrusted_wallet_provider_asserts_the_trusted_ones_policies() -> None:
    """W02's untrusted provider differs from the trusted one only in its CA, so an issuer that requires a signer
    policy cannot refuse it for the policy alone (the second reviewer)."""
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    from eudi_probe.attester import WalletProvider

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "trusted CA")])
    now = dt.datetime.now(dt.UTC)
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    trusted = WalletProvider.under(ca, key, ("1.2.3.4",))
    assert trusted.policies == ("1.2.3.4",)
    assert WalletProvider.untrusted(trusted.policies).policies == ("1.2.3.4",)
    assert WalletProvider.untrusted().policies == ()


def test_a_request_naming_both_identifiers_is_sent_as_it_is() -> None:
    """C07 names a configuration and an identifier on purpose; the token's identifiers must not rewrite it (the
    second reviewer), while a plain request by configuration is rewritten."""
    from eudi_probe.context import Token, with_identifier

    details = [{"type": "openid_credential", "credential_configuration_id": "pid", "credential_identifiers": ["id-1"]}]
    exchange = Exchange("POST", "/token", 200, {}, json.dumps({"authorization_details": details}))
    token = Token("t", EcKey.generate(), exchange)
    both = {"credential_configuration_id": "pid", "credential_identifier": "x"}
    assert with_identifier(token, both) == both
    assert with_identifier(token, {"credential_configuration_id": "pid", "proofs": {}}) == {
        "credential_identifier": "id-1",
        "proofs": {},
    }


def test_the_browser_walk_follows_a_page_that_moves_on_by_itself() -> None:
    """A login service may answer a form with a page that moves on by refresh (the demo's screens do, so the CSP's
    form-action does not govern where the browser goes next); the probe follows it, as a browser does."""
    from eudi_probe.authcode import _Form

    page = _Form()
    page.feed(
        '<html><head><meta http-equiv="refresh" content="0; url=https://issuer.test/authorize/continue?a=1&amp;b=2">'
        '</head><body><a href="https://issuer.test/x">Continue</a></body></html>'
    )
    assert page.action is None and page.refresh == "https://issuer.test/authorize/continue?a=1&b=2"
    for content in ("5", "0;", "0; target=x"):
        other = _Form()
        other.feed(f'<meta http-equiv="Refresh" content="{content}">')
        assert other.refresh is None, content
    quoted = _Form()
    quoted.feed('<meta http-equiv="refresh" content="0;URL=\'/next\'">')
    assert quoted.refresh == "/next"
