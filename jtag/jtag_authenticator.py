#!/usr/bin/env python3
"""Sign a device-provided JTAG challenge using the shared artifact signer."""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys
import tempfile


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SIGNER = REPOSITORY_ROOT / "signing" / "sign_artifact.py"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nonce-file", required=True, help="binary nonce received from the device")
    parser.add_argument("--out", required=True, help="challenge signature envelope output")
    parser.add_argument("--method", choices=("openssl", "pki"), required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--cert")
    parser.add_argument("--chain")
    arguments = parser.parse_args()
    command = [
        sys.executable, str(SIGNER), "--method", arguments.method, "--key", arguments.key,
        "--in", arguments.nonce_file, "--out", arguments.out,
    ]
    if arguments.cert:
        command.extend(("--cert", arguments.cert))
    if arguments.chain:
        command.extend(("--chain", arguments.chain))
    return subprocess.run(command, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())