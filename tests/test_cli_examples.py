"""The documented example packages: one intact, one with a single flipped bit."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from apps.cli_verifier.main import run_cli

ROOT = Path(__file__).resolve().parents[1]
VALID = ROOT / "examples" / "bundle_valid.json"
CORRUPT = ROOT / "examples" / "bundle_corrupted.json"


def _documented_command(bundle: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel_verify.cli",
            "--trust-store",
            str(bundle),
            "--bundle",
            str(bundle),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_valid_bundle_is_verified(capsys: pytest.CaptureFixture[str]) -> None:
    assert VALID.is_file()
    code = run_cli(["--trust-store", str(VALID), "--bundle", str(VALID)])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "VERIFIED"
    assert payload["violations"] == []


def test_one_bit_bundle_is_rejected(capsys: pytest.CaptureFixture[str]) -> None:
    assert CORRUPT.is_file()
    code = run_cli(["--trust-store", str(CORRUPT), "--bundle", str(CORRUPT)])
    assert code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "FAILED"
    assert payload["violations"]


def test_documented_command_verifies_intact_package() -> None:
    completed = _documented_command(VALID)
    assert completed.returncode == 0
    assert json.loads(completed.stdout)["status"] == "VERIFIED"


def test_documented_command_rejects_one_bit_package() -> None:
    completed = _documented_command(CORRUPT)
    assert completed.returncode == 1
    assert json.loads(completed.stdout)["status"] == "FAILED"


def test_corrupted_bundle_flips_one_signature_bit() -> None:
    valid = json.loads(VALID.read_text(encoding="utf-8"))
    corrupt = json.loads(CORRUPT.read_text(encoding="utf-8"))
    signature_valid = valid["entries"][0]["receipt"]["ed25519_signature_hex"]
    signature_corrupt = corrupt["entries"][0]["receipt"]["ed25519_signature_hex"]
    raw_valid = bytes.fromhex(signature_valid)
    raw_corrupt = bytes.fromhex(signature_corrupt)
    difference = bytes(left ^ right for left, right in zip(raw_valid, raw_corrupt, strict=True))
    assert sum(byte.bit_count() for byte in difference) == 1
    corrupt["entries"][0]["receipt"]["ed25519_signature_hex"] = signature_valid
    assert corrupt == valid


def test_examples_embed_public_keys_only() -> None:
    for path in (VALID, CORRUPT):
        text = path.read_text(encoding="utf-8").lower()
        assert "private_key" not in text
        assert "postgres://" not in text
        assert "begin private" not in text
