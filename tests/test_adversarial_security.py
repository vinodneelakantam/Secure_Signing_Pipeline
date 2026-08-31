from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SIGNER = REPOSITORY_ROOT / "signing" / "sign_artifact.py"
VERIFIER = REPOSITORY_ROOT / "signing" / "verify_artifact.py"
PKI_GENERATOR = REPOSITORY_ROOT / "signing" / "pki" / "gen_ca_hierarchy.sh"


def run(*command: str, expected_returncode: int = 0) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != expected_returncode:
        raise AssertionError(
            f"expected exit {expected_returncode}, got {result.returncode}: {' '.join(command)}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return result


class AdversarialSigningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(prefix="adversarial-signing-")
        self.directory = Path(self.temporary_directory.name)
        self.artifact = self.directory / "artifact.bin"
        self.artifact.write_bytes(b"protected automotive artifact")
        self.key = self.directory / "signer.key"
        self.public_key = self.directory / "signer.pub"
        self.envelope = self.directory / "artifact.sig"
        run("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(self.key))
        run("openssl", "ec", "-in", str(self.key), "-pubout", "-out", str(self.public_key))
        run(sys.executable, str(SIGNER), "--method", "openssl", "--key", str(self.key), "--in", str(self.artifact), "--out", str(self.envelope))

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def assert_verification_rejected(self, envelope: Path, public_key: Path | None = None, root_ca: Path | None = None) -> None:
        command = [sys.executable, str(VERIFIER), "--in", str(self.artifact), "--signature", str(envelope)]
        if public_key:
            command.extend(("--public-key", str(public_key)))
        if root_ca:
            command.extend(("--root-ca", str(root_ca)))
        run(*command, expected_returncode=1)

    def test_rejects_malformed_or_downgraded_envelopes(self) -> None:
        cases = {
            "not-json.sig": "not json\n",
            "bad-format.sig": json.dumps({"format": "v0"}),
            "bad-method.sig": json.dumps({"format": "secure-signing-envelope/v1", "method": "none", "digest_algorithm": "sha256", "artifact_sha256": "0", "signature_base64": "AA=="}),
            "bad-base64.sig": json.dumps({"format": "secure-signing-envelope/v1", "method": "openssl", "digest_algorithm": "sha256", "artifact_sha256": "0", "signature_base64": "%%%"}),
        }
        for name, contents in cases.items():
            candidate = self.directory / name
            candidate.write_text(contents, encoding="utf-8")
            with self.subTest(envelope=name):
                self.assert_verification_rejected(candidate, public_key=self.public_key)

    def test_rejects_signing_key_substitution(self) -> None:
        attacker_key = self.directory / "attacker.key"
        attacker_public_key = self.directory / "attacker.pub"
        attacker_envelope = self.directory / "attacker.sig"
        run("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(attacker_key))
        run("openssl", "ec", "-in", str(attacker_key), "-pubout", "-out", str(attacker_public_key))
        run(sys.executable, str(SIGNER), "--method", "openssl", "--key", str(attacker_key), "--in", str(self.artifact), "--out", str(attacker_envelope))
        self.assert_verification_rejected(attacker_envelope, public_key=self.public_key)

    def test_rejects_untrusted_pki_root_and_mismatched_leaf_key(self) -> None:
        trusted_pki = self.directory / "trusted-pki"
        untrusted_pki = self.directory / "untrusted-pki"
        pki_envelope = self.directory / "pki.sig"
        run(str(PKI_GENERATOR), str(trusted_pki))
        run(str(PKI_GENERATOR), str(untrusted_pki))
        run(sys.executable, str(SIGNER), "--method", "pki", "--key", str(trusted_pki / "leaf.key"), "--cert", str(trusted_pki / "leaf.pem"), "--chain", str(trusted_pki / "intermediate.pem"), "--in", str(self.artifact), "--out", str(pki_envelope))
        self.assert_verification_rejected(pki_envelope, root_ca=untrusted_pki / "root.pem")
        run(sys.executable, str(SIGNER), "--method", "pki", "--key", str(untrusted_pki / "leaf.key"), "--cert", str(trusted_pki / "leaf.pem"), "--chain", str(trusted_pki / "intermediate.pem"), "--in", str(self.artifact), "--out", str(self.directory / "mismatch.sig"), expected_returncode=1)


if __name__ == "__main__":
    unittest.main()