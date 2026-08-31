#!/usr/bin/env python3
"""Dynamic fuzz testing (DAST-style) of the verify_artifact.py process boundary.

Unlike the fixed adversarial unit tests, this generates randomized malformed input and
asserts the running verifier process only ever exits cleanly (0 or 1) and never crashes
with a traceback, segfault, or hang. It targets this repository's own tool, not an
external network target.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import string
import subprocess
import sys
import tempfile
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
VERIFIER = REPOSITORY_ROOT / "signing" / "verify_artifact.py"
TIMEOUT_SECONDS = 5


def random_bytes(random_generator: random.Random, maximum_length: int) -> bytes:
    return bytes(random_generator.randrange(0, 256) for _ in range(random_generator.randrange(0, maximum_length)))


def random_text(random_generator: random.Random, maximum_length: int) -> str:
    alphabet = string.ascii_letters + string.digits + '{}[]":,.-_/\\%$#@!\n\t'
    return "".join(random_generator.choice(alphabet) for _ in range(random_generator.randrange(0, maximum_length)))


def random_envelope(random_generator: random.Random) -> str:
    if random_generator.random() < 0.5:
        return random_text(random_generator, 400)
    envelope = {
        "format": random_generator.choice(["secure-signing-envelope/v1", "", "v0", random_text(random_generator, 20)]),
        "method": random_generator.choice(["openssl", "pki", "", "none", random_text(random_generator, 10)]),
        "digest_algorithm": random_generator.choice(["sha256", "md5", "", random_text(random_generator, 10)]),
        "artifact_sha256": random_generator.choice(["", random_text(random_generator, 64), None]),
        "signature_base64": random_generator.choice(["", "%%%not-base64%%%", random_text(random_generator, 120), None]),
        "certificate_pem": random_generator.choice([None, "", random_text(random_generator, 200)]),
        "chain_pem": random_generator.choice([None, "", random_text(random_generator, 200)]),
    }
    return json.dumps(envelope)


def run_one_case(random_generator: random.Random, directory: Path) -> tuple[int, str]:
    artifact = directory / "artifact.bin"
    envelope = directory / "artifact.sig"
    artifact.write_bytes(random_bytes(random_generator, 64) or b"seed")
    envelope.write_text(random_envelope(random_generator), encoding="utf-8")

    command = [sys.executable, str(VERIFIER), "--in", str(artifact), "--signature", str(envelope)]
    if random_generator.random() < 0.5:
        command.extend(("--public-key", str(directory / "missing.pub")))
    else:
        command.extend(("--root-ca", str(directory / "missing-root.pem")))

    try:
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=TIMEOUT_SECONDS, check=False
        )
    except subprocess.TimeoutExpired:
        return -1, "process hung past timeout"
    if result.returncode not in (0, 1):
        return result.returncode, result.stderr.decode("utf-8", errors="replace")
    if b"Traceback (most recent call last)" in result.stderr:
        return result.returncode, "unhandled Python traceback reached the process boundary"
    return 0, ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=200)
    parser.add_argument("--seed", type=int, default=None)
    arguments = parser.parse_args()
    seed = arguments.seed if arguments.seed is not None else int.from_bytes(os.urandom(4), "big")
    random_generator = random.Random(seed)

    with tempfile.TemporaryDirectory(prefix="dast-fuzz-verify-") as temporary_directory:
        directory = Path(temporary_directory)
        for iteration in range(arguments.iterations):
            status, detail = run_one_case(random_generator, directory)
            if status != 0:
                print(f"FAIL at iteration {iteration} (seed={seed}): {detail}", file=sys.stderr)
                return 1

    print(f"OK: {arguments.iterations} randomized verify_artifact.py inputs failed closed (seed={seed})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
