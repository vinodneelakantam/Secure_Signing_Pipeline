from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SIGNER = REPOSITORY_ROOT / "signing" / "sign_artifact.py"
VERIFIER = REPOSITORY_ROOT / "signing" / "verify_artifact.py"


def run(*command: str, expected_returncode: int = 0) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != expected_returncode:
        raise AssertionError(
            f"expected exit {expected_returncode}, got {result.returncode}: {' '.join(command)}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return result


def generate_ec_key(path: Path) -> None:
    run("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(path))


class SigningRoundTripTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(prefix="secure-signing-test-")
        self.directory = Path(self.temporary_directory.name)
        self.artifact = self.directory / "artifact.bin"
        self.artifact.write_bytes(b"automotive firmware artifact\x00v1")

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_openssl_signature_round_trip_and_tamper_rejection(self) -> None:
        key = self.directory / "signing.key"
        public_key = self.directory / "signing.pub"
        envelope = self.directory / "artifact.sig"
        generate_ec_key(key)
        run("openssl", "ec", "-in", str(key), "-pubout", "-out", str(public_key))

        run(sys.executable, str(SIGNER), "--method", "openssl", "--key", str(key), "--in", str(self.artifact), "--out", str(envelope))
        run(sys.executable, str(VERIFIER), "--in", str(self.artifact), "--signature", str(envelope), "--public-key", str(public_key))

        self.artifact.write_bytes(b"tampered")
        run(sys.executable, str(VERIFIER), "--in", str(self.artifact), "--signature", str(envelope), "--public-key", str(public_key), expected_returncode=1)

    def test_pki_signature_round_trip(self) -> None:
        root_key = self.directory / "root.key"
        root_certificate = self.directory / "root.pem"
        intermediate_key = self.directory / "intermediate.key"
        intermediate_request = self.directory / "intermediate.csr"
        intermediate_certificate = self.directory / "intermediate.pem"
        leaf_key = self.directory / "leaf.key"
        leaf_request = self.directory / "leaf.csr"
        leaf_certificate = self.directory / "leaf.pem"
        chain = self.directory / "chain.pem"
        extensions = self.directory / "extensions.cnf"
        envelope = self.directory / "artifact.sig"

        extensions.write_text(
            "[intermediate_ca]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n"
            "[leaf]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n",
            encoding="utf-8",
        )
        generate_ec_key(root_key)
        run("openssl", "req", "-x509", "-new", "-key", str(root_key), "-sha256", "-days", "1", "-subj", "/CN=Test Root", "-out", str(root_certificate))
        generate_ec_key(intermediate_key)
        run("openssl", "req", "-new", "-key", str(intermediate_key), "-subj", "/CN=Test Intermediate", "-out", str(intermediate_request))
        run("openssl", "x509", "-req", "-in", str(intermediate_request), "-CA", str(root_certificate), "-CAkey", str(root_key), "-CAcreateserial", "-days", "1", "-sha256", "-extfile", str(extensions), "-extensions", "intermediate_ca", "-out", str(intermediate_certificate))
        generate_ec_key(leaf_key)
        run("openssl", "req", "-new", "-key", str(leaf_key), "-subj", "/CN=Artifact Signer", "-out", str(leaf_request))
        run("openssl", "x509", "-req", "-in", str(leaf_request), "-CA", str(intermediate_certificate), "-CAkey", str(intermediate_key), "-CAcreateserial", "-days", "1", "-sha256", "-extfile", str(extensions), "-extensions", "leaf", "-out", str(leaf_certificate))
        chain.write_bytes(intermediate_certificate.read_bytes())

        run(sys.executable, str(SIGNER), "--method", "pki", "--key", str(leaf_key), "--cert", str(leaf_certificate), "--chain", str(chain), "--in", str(self.artifact), "--out", str(envelope))
        run(sys.executable, str(VERIFIER), "--in", str(self.artifact), "--signature", str(envelope), "--root-ca", str(root_certificate))


if __name__ == "__main__":
    unittest.main()