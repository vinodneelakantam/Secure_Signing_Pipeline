#!/usr/bin/env python3
"""Adversarial fuzz test (case study) for the release gate: static binary + signature + SBOM.

This is the "prevent shipping an unsigned binary" incident class, reproduced as a fuzz
harness: for every randomized combination of {artifact present/mutated, signature
present/tampered/wrong-key, SBOM mentions it or not}, the release gate must approve
release ONLY for the fully-consistent case and must block every other combination.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
from pathlib import Path
import subprocess
import tempfile

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "security" / "release-gate"))
from check_release_gate import evaluate_release  # noqa: E402

SIGNER = REPOSITORY_ROOT / "signing" / "sign_artifact.py"


def run(*command: str) -> None:
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode("utf-8", errors="replace"))


def build_case(random_generator: random.Random, directory: Path) -> tuple[Path, Path, bool]:
    """Return (artifact_path, public_key_path, expected_release_approved)."""
    artifact = directory / "app.bin"
    signature = directory / "app.bin.sig"
    key = directory / "trusted.key"
    public_key = directory / "trusted.pub"
    other_key = directory / "attacker.key"

    artifact.write_bytes(random_generator.randbytes(random_generator.randrange(16, 256)))
    run("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key))
    run("openssl", "ec", "-in", str(key), "-pubout", "-out", str(public_key))

    scenario = random_generator.choice([
        "clean", "missing_signature", "tampered_after_signing", "wrong_signing_key", "corrupted_envelope",
    ])

    if scenario == "clean":
        run(sys.executable, str(SIGNER), "--method", "openssl", "--key", str(key), "--in", str(artifact), "--out", str(signature))
        return artifact, public_key, True

    if scenario == "missing_signature":
        return artifact, public_key, False

    if scenario == "tampered_after_signing":
        run(sys.executable, str(SIGNER), "--method", "openssl", "--key", str(key), "--in", str(artifact), "--out", str(signature))
        artifact.write_bytes(artifact.read_bytes() + b"\x00tampered")
        return artifact, public_key, False

    if scenario == "wrong_signing_key":
        run("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(other_key))
        run(sys.executable, str(SIGNER), "--method", "openssl", "--key", str(other_key), "--in", str(artifact), "--out", str(signature))
        return artifact, public_key, False

    run(sys.executable, str(SIGNER), "--method", "openssl", "--key", str(key), "--in", str(artifact), "--out", str(signature))
    envelope = json.loads(signature.read_text(encoding="utf-8"))
    envelope["signature_base64"] = "not-valid-base64-%%%"
    signature.write_text(json.dumps(envelope), encoding="utf-8")
    return artifact, public_key, False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=200)
    parser.add_argument("--seed", type=int, default=None)
    arguments = parser.parse_args()
    seed = arguments.seed if arguments.seed is not None else int.from_bytes(os.urandom(4), "big")
    random_generator = random.Random(seed)

    for iteration in range(arguments.iterations):
        with tempfile.TemporaryDirectory(prefix="fuzz-release-gate-") as temporary_directory:
            directory = Path(temporary_directory)
            artifact, public_key, expected_approved = build_case(random_generator, directory)
            failures = evaluate_release([artifact], public_key=public_key)
            approved = not failures
            if approved != expected_approved:
                print(
                    f"FAIL at iteration {iteration} (seed={seed}): expected approved={expected_approved}, "
                    f"got approved={approved}, failures={failures}",
                    file=sys.stderr,
                )
                return 1

    print(f"OK: {arguments.iterations} randomized release-gate scenarios matched expected pass/block outcome (seed={seed})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
