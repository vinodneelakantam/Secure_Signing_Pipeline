#!/usr/bin/env python3
"""Verify a secure-signing-envelope/v1 against an artifact and trusted key material."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


class VerificationError(RuntimeError):
    pass


def run_openssl(*arguments: str) -> bytes:
    try:
        result = subprocess.run(
            ["openssl", *arguments], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True
        )
    except FileNotFoundError as error:
        raise VerificationError("openssl is required but was not found on PATH") from error
    except subprocess.CalledProcessError as error:
        message = error.stderr.decode("utf-8", errors="replace").strip()
        raise VerificationError(message or "openssl verification failed") from error
    return result.stdout


def load_envelope(path: Path) -> dict[str, object]:
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise VerificationError(f"invalid signature envelope: {error}") from error
    if not isinstance(envelope, dict) or envelope.get("format") != "secure-signing-envelope/v1":
        raise VerificationError("unsupported signature envelope format")
    if envelope.get("method") not in ("openssl", "pki"):
        raise VerificationError("unsupported signature envelope method")
    if envelope.get("digest_algorithm") != "sha256":
        raise VerificationError("unsupported digest algorithm")
    if not isinstance(envelope.get("artifact_sha256"), str):
        raise VerificationError("envelope is missing artifact_sha256")
    if not isinstance(envelope.get("signature_base64"), str):
        raise VerificationError("envelope is missing signature_base64")
    return envelope


def verify(arguments: argparse.Namespace) -> None:
    artifact = Path(arguments.input)
    signature = Path(arguments.signature)
    if not artifact.is_file():
        raise VerificationError(f"artifact does not exist: {artifact}")
    if not signature.is_file():
        raise VerificationError(f"signature envelope does not exist: {signature}")
    envelope = load_envelope(signature)
    actual_digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    if actual_digest != envelope["artifact_sha256"]:
        raise VerificationError("artifact SHA-256 does not match the signed digest")

    try:
        signature_bytes = base64.b64decode(envelope["signature_base64"], validate=True)
    except (ValueError, TypeError) as error:
        raise VerificationError("signature_base64 is malformed") from error

    with tempfile.TemporaryDirectory(prefix="secure-verification-") as temporary_directory:
        directory = Path(temporary_directory)
        raw_signature = directory / "artifact.sig"
        raw_signature.write_bytes(signature_bytes)
        if envelope["method"] == "openssl":
            if not arguments.public_key:
                raise VerificationError("OpenSSL verification requires --public-key")
            public_key = Path(arguments.public_key)
            if not public_key.is_file():
                raise VerificationError(f"public key does not exist: {public_key}")
        else:
            if not arguments.root_ca:
                raise VerificationError("PKI verification requires --root-ca")
            if not isinstance(envelope.get("certificate_pem"), str) or not isinstance(envelope.get("chain_pem"), str):
                raise VerificationError("PKI envelope is missing its certificate chain")
            certificate = directory / "leaf.pem"
            chain = directory / "chain.pem"
            public_key = directory / "leaf.pub"
            certificate.write_text(envelope["certificate_pem"], encoding="utf-8")
            chain.write_text(envelope["chain_pem"], encoding="utf-8")
            run_openssl("verify", "-CAfile", arguments.root_ca, "-untrusted", str(chain), str(certificate))
            public_key.write_bytes(run_openssl("x509", "-in", str(certificate), "-pubkey", "-noout"))

        run_openssl(
            "dgst", "-sha256", "-verify", str(public_key), "-signature", str(raw_signature), str(artifact)
        )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--in", dest="input", required=True, help="artifact to verify")
    parser.add_argument("--signature", required=True, help="signature envelope path")
    parser.add_argument("--public-key", help="trusted public key for openssl envelopes")
    parser.add_argument("--root-ca", help="pinned root CA PEM for pki envelopes")
    return parser.parse_args()


def main() -> int:
    try:
        verify(parse_arguments())
    except (OSError, VerificationError) as error:
        print(f"verify_artifact: {error}", flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())