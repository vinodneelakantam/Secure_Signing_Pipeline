#!/usr/bin/env python3
"""Create a detached, portable signature envelope for one build artifact."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


class SigningError(RuntimeError):
    pass


def run_openssl(*arguments: str, input_data: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(
            ["openssl", *arguments],
            input=input_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
    except FileNotFoundError as error:
        raise SigningError("openssl is required but was not found on PATH") from error
    except subprocess.CalledProcessError as error:
        message = error.stderr.decode("utf-8", errors="replace").strip()
        raise SigningError(f"openssl {' '.join(arguments[:2])} failed: {message}") from error
    return result.stdout


def read_text(path: Path) -> str:
    if not path.is_file():
        raise SigningError(f"file does not exist: {path}")
    return path.read_text(encoding="utf-8")


def ensure_key_matches_certificate(key: Path, certificate: Path) -> None:
    key_public = run_openssl("pkey", "-in", str(key), "-pubout")
    certificate_public = run_openssl("x509", "-in", str(certificate), "-pubkey", "-noout")
    if key_public != certificate_public:
        raise SigningError("the supplied private key does not match the leaf certificate")


def sign(arguments: argparse.Namespace) -> None:
    artifact = Path(arguments.input)
    private_key = Path(arguments.key)
    output = Path(arguments.output)
    artifact_bytes = artifact.read_bytes() if artifact.is_file() else None
    if artifact_bytes is None:
        raise SigningError(f"artifact does not exist: {artifact}")
    if not private_key.is_file():
        raise SigningError(f"private key does not exist: {private_key}")

    envelope: dict[str, object] = {
        "format": "secure-signing-envelope/v1",
        "method": arguments.method,
        "digest_algorithm": "sha256",
        "artifact_sha256": hashlib.sha256(artifact_bytes).hexdigest(),
    }
    if arguments.method == "pki":
        certificate = Path(arguments.cert) if arguments.cert else None
        chain = Path(arguments.chain) if arguments.chain else None
        if certificate is None or chain is None:
            raise SigningError("PKI signing requires --cert and --chain")
        ensure_key_matches_certificate(private_key, certificate)
        envelope["certificate_pem"] = read_text(certificate)
        envelope["chain_pem"] = read_text(chain)

    with tempfile.TemporaryDirectory(prefix="secure-signing-") as temporary_directory:
        signature_path = Path(temporary_directory) / "artifact.sig"
        run_openssl(
            "dgst", "-sha256", "-sign", str(private_key), "-out", str(signature_path), str(artifact)
        )
        envelope["signature_base64"] = base64.b64encode(signature_path.read_bytes()).decode("ascii")

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(envelope, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--method", choices=("openssl", "pki"), required=True)
    parser.add_argument("--key", required=True, help="private key used for signing")
    parser.add_argument("--cert", help="leaf certificate PEM (required for pki)")
    parser.add_argument("--chain", help="intermediate CA certificate chain PEM (required for pki)")
    parser.add_argument("--in", dest="input", required=True, help="artifact to sign")
    parser.add_argument("--out", dest="output", required=True, help="signature envelope output path")
    return parser.parse_args()


def main() -> int:
    try:
        sign(parse_arguments())
    except (OSError, SigningError) as error:
        print(f"sign_artifact: {error}", flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())