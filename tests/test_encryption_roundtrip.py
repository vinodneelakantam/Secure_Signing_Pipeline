from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
KEYGEN = REPOSITORY_ROOT / "signing" / "aes" / "gen_confidentiality_key.sh"
ENCRYPTOR = REPOSITORY_ROOT / "signing" / "encrypt_artifact.py"
DECRYPTOR = REPOSITORY_ROOT / "signing" / "decrypt_artifact.py"


def run(*command: str, expected_returncode: int = 0) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != expected_returncode:
        raise AssertionError(
            f"expected exit {expected_returncode}, got {result.returncode}: {' '.join(command)}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return result


class EncryptionRoundTripTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(prefix="secure-encryption-test-")
        self.directory = Path(self.temporary_directory.name)
        self.plaintext = self.directory / "artifact.bin"
        self.plaintext.write_bytes(b"proprietary automotive calibration payload\x00v1")
        self.key = self.directory / "confidentiality.key"
        run(str(KEYGEN), str(self.directory))

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_round_trip_recovers_original_bytes(self) -> None:
        envelope = self.directory / "artifact.bin.enc"
        recovered = self.directory / "artifact.bin.recovered"
        run(sys.executable, str(ENCRYPTOR), "--key", str(self.key), "--in", str(self.plaintext), "--out", str(envelope))
        run(sys.executable, str(DECRYPTOR), "--key", str(self.key), "--envelope", str(envelope), "--out", str(recovered))
        self.assertEqual(recovered.read_bytes(), self.plaintext.read_bytes())

    def test_tampered_ciphertext_is_rejected_before_decryption(self) -> None:
        import base64
        import json

        envelope = self.directory / "artifact.bin.enc"
        recovered = self.directory / "artifact.bin.recovered"
        run(sys.executable, str(ENCRYPTOR), "--key", str(self.key), "--in", str(self.plaintext), "--out", str(envelope))

        data = json.loads(envelope.read_text(encoding="utf-8"))
        tampered = bytearray(base64.b64decode(data["ciphertext_base64"]))
        tampered[0] ^= 0xFF
        data["ciphertext_base64"] = base64.b64encode(bytes(tampered)).decode("ascii")
        envelope.write_text(json.dumps(data), encoding="utf-8")

        run(sys.executable, str(DECRYPTOR), "--key", str(self.key), "--envelope", str(envelope), "--out", str(recovered), expected_returncode=1)
        self.assertFalse(recovered.exists())

    def test_wrong_key_is_rejected(self) -> None:
        envelope = self.directory / "artifact.bin.enc"
        recovered = self.directory / "artifact.bin.recovered"
        wrong_key = self.directory / "wrong.key"
        run(str(KEYGEN), str(self.directory / "wrong"))
        wrong_key.write_bytes((self.directory / "wrong" / "confidentiality.key").read_bytes())

        run(sys.executable, str(ENCRYPTOR), "--key", str(self.key), "--in", str(self.plaintext), "--out", str(envelope))
        run(sys.executable, str(DECRYPTOR), "--key", str(wrong_key), "--envelope", str(envelope), "--out", str(recovered), expected_returncode=1)


if __name__ == "__main__":
    unittest.main()
