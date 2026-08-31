#!/usr/bin/env python3
"""Confidentiality companion to sign_artifact.py: AES-256-CBC encryption with an
independent HMAC-SHA256 authentication tag (Encrypt-then-MAC).

Signing (sign_artifact.py) gives integrity and authenticity: anyone with the public
key/cert can verify the artifact wasn't altered and came from the holder of the private
key, but the artifact contents remain fully readable. This module adds confidentiality
for artifacts that must not be readable in transit or at rest (e.g. proprietary
calibration data), independent of whether the artifact is also signed.

Recommended order: encrypt first, then sign the resulting .enc envelope with
sign_artifact.py, so the signature also covers the exact ciphertext bytes shipped.

Note: OpenSSL's `enc` CLI does not support AEAD ciphers (`enc: AEAD ciphers not
supported`), so this uses the classic, still-secure Encrypt-then-MAC construction
(AES-256-CBC + HMAC-SHA256) instead of AES-GCM, keeping the same "shell out to system
openssl, no extra Python crypto dependency" design as the rest of signing/.
"""

from __future__ import annotations

import argparse
import base64
import hmac
import json
from pathlib import Path
import subprocess

AES_KEY_BYTES = 32
MAC_KEY_BYTES = 32
KEY_FILE_BYTES = AES_KEY_BYTES + MAC_KEY_BYTES
IV_BYTES = 16


class EncryptionError(RuntimeError):
    pass


def run_openssl(*arguments: str, input_data: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(
            ["openssl", *arguments], input=input_data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True
        )
    except FileNotFoundError as error:
        raise EncryptionError("openssl is required but was not found on PATH") from error
    except subprocess.CalledProcessError as error:
        raise EncryptionError(error.stderr.decode("utf-8", errors="replace").strip()) from error
    return result.stdout


def load_key_parts(key_path: Path) -> tuple[bytes, bytes]:
    key_material = key_path.read_bytes()
    if len(key_material) != KEY_FILE_BYTES:
        raise EncryptionError(f"confidentiality key must be exactly {KEY_FILE_BYTES} raw bytes (32 AES + 32 HMAC)")
    return key_material[:AES_KEY_BYTES], key_material[AES_KEY_BYTES:]


def encrypt(arguments: argparse.Namespace) -> None:
    artifact = Path(arguments.input)
    if not artifact.is_file():
        raise EncryptionError(f"artifact does not exist: {artifact}")
    aes_key, mac_key = load_key_parts(Path(arguments.key))

    iv = run_openssl("rand", str(IV_BYTES))
    ciphertext = run_openssl(
        "enc", "-aes-256-cbc", "-K", aes_key.hex(), "-iv", iv.hex(), "-in", str(artifact)
    )
    tag = run_openssl("dgst", "-sha256", "-hmac", mac_key.hex(), "-binary", input_data=iv + ciphertext)

    envelope = {
        "format": "secure-encryption-envelope/v1",
        "cipher": "aes-256-cbc+hmac-sha256",
        "iv_base64": base64.b64encode(iv).decode("ascii"),
        "ciphertext_base64": base64.b64encode(ciphertext).decode("ascii"),
        "hmac_base64": base64.b64encode(tag).decode("ascii"),
    }
    output = Path(arguments.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(envelope, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--key", required=True, help="64-byte raw confidentiality key file (32 AES + 32 HMAC)")
    parser.add_argument("--in", dest="input", required=True, help="artifact to encrypt")
    parser.add_argument("--out", dest="output", required=True, help="encryption envelope output path")
    return parser.parse_args()


def main() -> int:
    try:
        encrypt(parse_arguments())
    except (OSError, EncryptionError) as error:
        print(f"encrypt_artifact: {error}", flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
