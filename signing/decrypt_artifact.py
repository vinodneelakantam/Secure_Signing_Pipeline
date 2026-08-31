#!/usr/bin/env python3
"""Companion to encrypt_artifact.py: verifies the HMAC tag before ever decrypting.

The HMAC is checked first, in constant time, over the exact bytes that were encrypted
(IV || ciphertext). Decryption only proceeds if that check passes, so a tampered
ciphertext or IV is rejected before any AES decryption is attempted.
"""

from __future__ import annotations

import argparse
import base64
import hmac
import json
from pathlib import Path

from encrypt_artifact import KEY_FILE_BYTES, EncryptionError, load_key_parts, run_openssl


class DecryptionError(RuntimeError):
    pass


def decrypt(arguments: argparse.Namespace) -> bytes:
    envelope_path = Path(arguments.envelope)
    if not envelope_path.is_file():
        raise DecryptionError(f"encryption envelope does not exist: {envelope_path}")
    try:
        envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise DecryptionError(f"invalid encryption envelope: {error}") from error

    if not isinstance(envelope, dict) or envelope.get("format") != "secure-encryption-envelope/v1":
        raise DecryptionError("unsupported encryption envelope format")
    if envelope.get("cipher") != "aes-256-cbc+hmac-sha256":
        raise DecryptionError("unsupported cipher")

    try:
        iv = base64.b64decode(envelope["iv_base64"], validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext_base64"], validate=True)
        tag = base64.b64decode(envelope["hmac_base64"], validate=True)
    except (KeyError, ValueError, TypeError) as error:
        raise DecryptionError(f"encryption envelope is malformed: {error}") from error

    aes_key, mac_key = load_key_parts(Path(arguments.key))
    expected_tag = run_openssl("dgst", "-sha256", "-hmac", mac_key.hex(), "-binary", input_data=iv + ciphertext)
    if not hmac.compare_digest(expected_tag, tag):
        raise DecryptionError("HMAC verification failed: ciphertext or IV was modified, or the key is wrong")

    return run_openssl("enc", "-d", "-aes-256-cbc", "-K", aes_key.hex(), "-iv", iv.hex(), input_data=ciphertext)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--key", required=True, help="64-byte raw confidentiality key file (32 AES + 32 HMAC)")
    parser.add_argument("--envelope", required=True, help="encryption envelope path")
    parser.add_argument("--out", required=True, help="decrypted artifact output path")
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        plaintext = decrypt(arguments)
    except (OSError, DecryptionError, EncryptionError) as error:
        print(f"decrypt_artifact: {error}", flush=True)
        return 1
    Path(arguments.out).write_bytes(plaintext)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
