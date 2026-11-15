"""tools/deploy_init.py, the demo stack's init step: what it leaves on the volume every service reads.

The stack mounts one `secrets` volume into both issuers and the demo service, which all run as one user, so a file
there is readable by whichever of them is taken over. The security review found every private key of the
development PKI left on it, among them a wallet provider's root key that both issuers trust, and the new signing
keys written to it as files during a renewal, while the services ran. These tests run the tool as the container
does, with SoftHSM2, and skip where it is not installed (CI installs it)."""

from __future__ import annotations

import importlib.util
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = (ROOT / "deploy" / "compose.yaml").read_text()
# What a service is configured to read of the PKI's private keys (deploy/compose.yaml).
READ_BY_A_SERVICE = {"pki/encryption.key", "pki/m3/ka-signer.key"}


def tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location("deploy_init_under_test", ROOT / "tools" / "deploy_init.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def stack(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[ModuleType, Path, Path]:
    """The tool and the two volumes of a stack that has just started for the first time."""
    if shutil.which("softhsm2-util") is None:
        pytest.skip("SoftHSM2 is not installed")
    init = tool()
    secrets_dir, softhsm = tmp_path / "secrets", tmp_path / "softhsm"
    secrets_dir.mkdir()
    softhsm.mkdir()
    monkeypatch.setenv("SOFTHSM2_CONF", str(softhsm / "softhsm2.conf"))
    monkeypatch.setenv("ISSUER_HOST", "issuer.localhost:8443")
    monkeypatch.setattr(sys, "path", list(sys.path))  # the tool adds to it; the next test gets it back as it was
    assert init.main(secrets_dir, softhsm, False, tmp_path / "public") == 0
    return init, secrets_dir, softhsm


def private_keys(secrets_dir: Path) -> set[str]:
    return {
        path.relative_to(secrets_dir).as_posix()
        for path in secrets_dir.rglob("*")
        if path.is_file() and b"PRIVATE KEY-----" in path.read_bytes()
    }


def tokens() -> list[str]:
    listing = subprocess.run(["softhsm2-util", "--show-slots"], capture_output=True, text=True, check=True).stdout
    return sorted(re.findall(r"Label:\s+(cunho-\S+)", listing))


def test_the_settings_of_the_stack_name_the_keys_it_keeps(stack: tuple[ModuleType, Path, Path]) -> None:
    init, _, _ = stack
    assert {f"pki/{name}" for name in init.KEPT} == READ_BY_A_SERVICE
    for name in READ_BY_A_SERVICE:
        assert f"/secrets/{name}" in COMPOSE, name


def test_a_first_start_leaves_only_the_keys_a_service_reads(stack: tuple[ModuleType, Path, Path]) -> None:
    _, secrets_dir, softhsm = stack
    assert private_keys(secrets_dir) == READ_BY_A_SERVICE
    assert not (secrets_dir / "pki" / "admin-token").exists(), "a local run's operator token is no use to the stack"
    assert not (secrets_dir / "pki.new").exists()
    assert tokens() == ["cunho-course", "cunho-pid"]
    for instance in ("pid", "course"):
        for name in (f"{instance}-pin", f"{instance}-admin-token", f"{instance}-master.key"):
            assert (secrets_dir / name).is_file(), name
    # The certificates the services are configured with are all there.
    for configured in sorted(set(re.findall(r"/secrets/(pki/[A-Za-z0-9._/-]+)", COMPOSE))):
        assert (secrets_dir / configured).is_file(), configured
    for path in (p for p in secrets_dir.rglob("*") if p.is_file()):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600, path
    assert not any(softhsm.glob("*.pem")), "no copy of a key is left beside the tokens"


def test_a_second_run_changes_nothing(stack: tuple[ModuleType, Path, Path], tmp_path: Path) -> None:
    init, secrets_dir, softhsm = stack
    before = {path: path.read_bytes() for path in secrets_dir.rglob("*") if path.is_file()}
    assert init.main(secrets_dir, softhsm, False, tmp_path / "public") == 0
    assert {path: path.read_bytes() for path in secrets_dir.rglob("*") if path.is_file()} == before
    assert tokens() == ["cunho-course", "cunho-pid"]


def test_a_renewal_never_puts_a_signing_key_where_the_running_services_read(
    stack: tuple[ModuleType, Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    init, secrets_dir, softhsm = stack
    kept = {name: (secrets_dir / name).read_bytes() for name in ("pid-admin-token", "course-master.key")}
    old_pin = (secrets_dir / "pid-pin").read_bytes()
    old_certificate = (secrets_dir / "pki" / "signing.pem").read_bytes()
    fill = init.token
    seen: set[str] = set()

    def watching(softhsm_dir: Path, built: Path, where: Path, instance: str) -> None:
        """The moment a token is filled: what a service that mounts the volume could read just then."""
        assert (built / "signing.key").is_file() and secrets_dir not in built.parents, "the keys are in the scratch"
        seen.update(private_keys(secrets_dir))
        fill(softhsm_dir, built, where, instance)
        seen.update(private_keys(secrets_dir))

    monkeypatch.setattr(init, "token", watching)
    assert init.main(secrets_dir, softhsm, True, tmp_path / "public") == 0
    assert seen == set(), "while the tokens were filled the volume held no private key at all"
    assert private_keys(secrets_dir) == READ_BY_A_SERVICE
    assert (secrets_dir / "pki" / "signing.pem").read_bytes() != old_certificate, "a new PKI"
    assert (secrets_dir / "pid-pin").read_bytes() != old_pin and tokens() == ["cunho-course", "cunho-pid"]
    for name, content in kept.items():
        assert (secrets_dir / name).read_bytes() == content, "operator tokens and secret keys are kept"


def test_a_volume_filled_by_the_earlier_tool_loses_the_keys_nobody_reads(
    stack: tuple[ModuleType, Path, Path], tmp_path: Path
) -> None:
    init, secrets_dir, softhsm = stack
    key = (secrets_dir / "pki" / "encryption.key").read_bytes()
    for left in ("wallet-provider.key", "tls.key", "m3/wia-signer.key", "m3/signing.key", "m3/lote-signer.key"):
        (secrets_dir / "pki" / left).write_bytes(key)
    (secrets_dir / "pki" / "admin-token").write_text("t" * 43)
    certificate = (secrets_dir / "pki" / "signing.pem").read_bytes()
    assert init.main(secrets_dir, softhsm, False, tmp_path / "public") == 0
    assert private_keys(secrets_dir) == READ_BY_A_SERVICE
    assert not (secrets_dir / "pki" / "admin-token").exists()
    assert (secrets_dir / "pki" / "signing.pem").read_bytes() == certificate, "the PKI itself is left as it is"


def test_a_run_cut_short_is_made_again_whole(stack: tuple[ModuleType, Path, Path], tmp_path: Path) -> None:
    """A run stopped before its last PIN was written has lost the keys of its scratch directory: the PKI and both
    tokens are made again together, never one token filled from a PKI that no longer has its keys."""
    init, secrets_dir, softhsm = stack
    certificate = (secrets_dir / "pki" / "signing.pem").read_bytes()
    (secrets_dir / "course-pin").unlink()
    assert init.main(secrets_dir, softhsm, False, tmp_path / "public") == 0
    assert (secrets_dir / "pki" / "signing.pem").read_bytes() != certificate
    assert tokens() == ["cunho-course", "cunho-pid"] and (secrets_dir / "course-pin").is_file()
    assert private_keys(secrets_dir) == READ_BY_A_SERVICE


def test_the_first_start_says_how_to_be_rid_of_the_password_it_prints(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    """What a container prints is kept with the container: the line that carries the password is followed by how to
    remove it, and a later run prints no password."""
    if shutil.which("softhsm2-util") is None:
        pytest.skip("SoftHSM2 is not installed")
    init = tool()
    secrets_dir, softhsm = tmp_path / "secrets", tmp_path / "softhsm"
    secrets_dir.mkdir()
    softhsm.mkdir()
    monkeypatch.setenv("SOFTHSM2_CONF", str(softhsm / "softhsm2.conf"))
    monkeypatch.setattr(sys, "path", list(sys.path))
    assert init.main(secrets_dir, softhsm) == 0
    first = capfd.readouterr().out
    assert "operator console password (shown once): " in first and "docker compose rm -f init" in first
    assert init.main(secrets_dir, softhsm) == 0
    assert "password" not in capfd.readouterr().out
