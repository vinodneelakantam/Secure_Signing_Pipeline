from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
AUTHENTICATOR = REPOSITORY_ROOT / "jtag" / "jtag_authenticator.py"
sys.path.insert(0, str(REPOSITORY_ROOT / "jtag"))
from jtag_device_simulator import DebugAuthenticationDevice


def run(*command: str, expected_returncode: int = 0) -> None:
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != expected_returncode:
        raise AssertionError(f"{' '.join(command)}\n{result.stdout}\n{result.stderr}")


class JtagChallengeResponseTests(unittest.TestCase):
    def test_valid_response_unlocks_once_and_replay_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="jtag-test-") as temporary_directory:
            directory = Path(temporary_directory)
            key = directory / "debug.key"
            public_key = directory / "debug.pub"
            nonce = directory / "nonce.bin"
            response = directory / "response.sig"
            wrong_nonce = directory / "wrong-nonce.bin"
            wrong_response = directory / "wrong-response.sig"
            run("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key))
            run("openssl", "ec", "-in", str(key), "-pubout", "-out", str(public_key))

            device = DebugAuthenticationDevice(public_key=public_key)
            nonce.write_bytes(device.request_unlock())
            run(sys.executable, str(AUTHENTICATOR), "--method", "openssl", "--key", str(key), "--nonce-file", str(nonce), "--out", str(response))
            self.assertTrue(device.submit_response(response))
            self.assertTrue(device.jtag_unlocked)
            self.assertFalse(device.submit_response(response))

            wrong_nonce.write_bytes(b"different nonce")
            run(sys.executable, str(AUTHENTICATOR), "--method", "openssl", "--key", str(key), "--nonce-file", str(wrong_nonce), "--out", str(wrong_response))
            device.request_unlock()
            self.assertFalse(device.submit_response(wrong_response))
            self.assertFalse(device.jtag_unlocked)


if __name__ == "__main__":
    unittest.main()