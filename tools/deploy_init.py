"""Prepare the demo stack's secrets once, inside its container (deploy/compose.yaml, service `init`).

Writes into /secrets, as the image's unprivileged user and readable by it alone:
- the certificates of a PKI for the demo (tools/dev_pki.py: issuer, status, mdoc and access certificates in the
  profiles cunho checks), and the two private keys a service reads from a file (KEPT);
- one SoftHSM2 token per cunho instance, `cunho-pid` and `cunho-course`, with every signing key imported into it, so
  each instance signs through PKCS#11 as a production deployment would; the user PIN of each token in
  `<instance>-pin`;
- each instance's operator token and secret key file, and the demo service's secret key;
- the operator console's password as an scrypt hash, the password itself printed once.

The PKI is made in this run's own scratch directory (the container's /tmp, which is memory) and its keys go from
there into the tokens: a signing key is never a file on the volume the running services read, at the first start or
at a renewal, and the keys no service uses (the development wallet providers' and the rest) never leave the scratch
directory, which goes with the run (the security review).

Run again, it leaves everything that exists alone: a token or a key is never made twice. With --renew, it makes a
new PKI and new tokens instead (the development PKI's certificates last 90 days and its CRLs 30): run it monthly and
restart the three services (the demo service holds the demo wallet's attestation signer of the PKI it started
with). Credentials issued before are then signed under a PKI nobody trusts any more, which a demo can live with; the
operator tokens, secret keys, store and audit log are kept.
Usage (in the container): python tools/deploy_init.py /secrets /softhsm [--renew] [--public DIR]
With --public, the IACA's CRL is copied into DIR, which Caddy serves at the distribution point the document signer
names (https://ISSUER_HOST/crl/iaca.crl).
"""

from __future__ import annotations

import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[1]
INSTANCES = ("pid", "course")
KEYS = {"signing": "signing.key", "status": "status.key", "mdoc": "mdoc-signing.key", "access": "m3/access.key"}
# The private keys a service reads from the volume: the key encrypted requests are made to (both issuers) and the
# demo wallet's key-attestation signer (the demo service).
KEPT = ("encryption.key", "m3/ka-signer.key")


def private(path: Path, data: bytes) -> None:
    """Write a file only cunho's user can read; never over an existing one."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)


def once(path: Path, make: bytes) -> None:
    if not path.exists():
        private(path, make)


def secret(path: Path) -> bool:
    """Whether a file of the PKI is private: a key, or the operator token dev_pki.py makes for a local run."""
    return path.suffix == ".key" or path.name == "admin-token"


def token(softhsm: Path, built: Path, secrets_dir: Path, instance: str) -> None:
    """A new token for one instance, filled with the signing keys of the PKI in `built`; its PIN is written last, so
    a token with its PIN was filled."""
    label = f"cunho-{instance}"
    pin = secrets.token_hex(16)
    so_pin = secrets.token_hex(16)  # never needed again: the token is made once and keys are only imported
    subprocess.run(
        ["softhsm2-util", "--init-token", "--free", "--label", label, "--pin", pin, "--so-pin", so_pin],
        check=True,
        capture_output=True,
    )
    try:
        for number, (name, file) in enumerate(KEYS.items(), start=1):
            key = serialization.load_pem_private_key((built / file).read_bytes(), None)
            pkcs8 = key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
            with tempfile.NamedTemporaryFile(dir=built, suffix=".pem") as handle:  # beside the keys: in the scratch
                handle.write(pkcs8)
                handle.flush()
                subprocess.run(
                    ["softhsm2-util", "--import", handle.name, "--token", label, "--label", name]
                    + ["--id", f"{number:02x}", "--pin", pin],
                    check=True,
                    capture_output=True,
                )
        private(secrets_dir / f"{instance}-pin", pin.encode())
    except BaseException:
        # A token half filled goes; the next run finds the PKI or a PIN missing and makes everything again.
        subprocess.run(["softhsm2-util", "--delete-token", "--token", label], check=False, capture_output=True)
        raise


def renew(secrets_dir: Path, softhsm: Path) -> None:
    """Drop the PKI and the tokens, so the run that follows makes both again."""
    shutil.rmtree(secrets_dir / "pki", ignore_errors=True)
    for instance in INSTANCES:
        subprocess.run(
            ["softhsm2-util", "--delete-token", "--token", f"cunho-{instance}"], check=False, capture_output=True
        )
        (secrets_dir / f"{instance}-pin").unlink(missing_ok=True)


def publish(built: Path, pki: Path) -> None:
    """Copy to the volume what the services read: every certificate, CRL and document of the PKI, and of its private
    keys only KEPT. Made aside and renamed into place, so a PKI cut short is never taken as made."""
    aside = pki.with_name("pki.new")
    shutil.rmtree(aside, ignore_errors=True)
    for source in sorted(p for p in built.rglob("*") if p.is_file()):
        name = source.relative_to(built)
        if secret(source) and name.as_posix() not in KEPT:
            continue
        (aside / name).parent.mkdir(parents=True, exist_ok=True)
        private(aside / name, source.read_bytes())  # cunho reads key files only when its user alone can
    aside.rename(pki)


def main(secrets_dir: Path, softhsm: Path, renewing: bool = False, public: Path | None = None) -> int:
    pki = secrets_dir / "pki"
    filled = pki.exists() and all((secrets_dir / f"{instance}-pin").exists() for instance in INSTANCES)
    if renewing or not filled:
        # Also after a run that was cut short: the keys it made went with its scratch directory, so the PKI and
        # both tokens are made again together.
        renew(secrets_dir, softhsm)
    (softhsm / "tokens").mkdir(parents=True, exist_ok=True)
    conf = softhsm / "softhsm2.conf"
    if not conf.exists():
        conf.write_text(f"directories.tokendir = {softhsm / 'tokens'}\nobjectstore.backend = file\nlog.level = ERROR\n")
    if not pki.exists():
        with tempfile.TemporaryDirectory() as scratch:
            built = Path(scratch) / "pki"
            # The credential signer names the issuers' host (SD-JWT VC §3.5); both instances share it.
            issuers = os.environ.get("ISSUER_HOST", "localhost")
            host = urlsplit(f"https://{issuers}").hostname or "localhost"
            # The document signer names where its IACA's CRL is published: on the issuers' host, by Caddy.
            env = dict(os.environ, DEV_PKI_CRL_URL=f"https://{issuers}/crl/iaca.crl")
            subprocess.run([sys.executable, str(ROOT / "tools" / "dev_pki.py"), str(built), host], check=True, env=env)
            for instance in INSTANCES:
                token(softhsm, built, secrets_dir, instance)
            publish(built, pki)
    # A volume filled by an earlier version of this tool kept every key of the development PKI: those go.
    for path in sorted(p for p in pki.rglob("*") if p.is_file()):
        if secret(path) and path.relative_to(pki).as_posix() not in KEPT:
            path.unlink()
    for instance in INSTANCES:
        once(secrets_dir / f"{instance}-admin-token", secrets.token_urlsafe(32).encode())
        once(secrets_dir / f"{instance}-master.key", secrets.token_bytes(32))
    once(secrets_dir / "demo-secret.key", secrets.token_bytes(32))
    # The one file Caddy publishes from here, at the CRL distribution point the document signer names; renewed
    # with the PKI, whose CRLs last 30 days.
    if public is not None:
        public.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(pki / "iaca.crl", public / "iaca.crl")
        (public / "iaca.crl").chmod(0o644)
    if not (secrets_dir / "operator-password").exists():
        sys.path.insert(0, str(ROOT / "src"))
        from cunho_demo.console import hash_password  # noqa: PLC0415 - the image's demo package

        password = secrets.token_urlsafe(15)
        private(secrets_dir / "operator-password", hash_password(password).encode())
        print(f"operator console password (shown once): {password}")
        # What a container prints is kept with the container: say how to be rid of it (the security review).
        print("it stays in this container's log until the container is removed: docker compose rm -f init")
    print(f"secrets ready in {secrets_dir}")
    return 0


if __name__ == "__main__":
    options = sys.argv[3:]
    published = Path(options[options.index("--public") + 1]) if "--public" in options else None
    sys.exit(main(Path(sys.argv[1]), Path(sys.argv[2]), "--renew" in options, published))
