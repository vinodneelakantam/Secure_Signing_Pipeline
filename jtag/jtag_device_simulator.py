"""Reference model for one-time JTAG debug authentication.

Hardware must put this responsibility in boot ROM or a dedicated secure element. This model
exists solely to exercise the host protocol in CI and QEMU-oriented development.
"""

from __future__ import annotations

import secrets
from pathlib import Path
import subprocess
import sys
import tempfile


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
VERIFIER = REPOSITORY_ROOT / "signing" / "verify_artifact.py"


class DebugAuthenticationDevice:
    def __init__(self, *, public_key: Path | None = None, root_ca: Path | None = None) -> None:
        if (public_key is None) == (root_ca is None):
            raise ValueError("configure exactly one of public_key or root_ca")
        self.public_key = public_key
        self.root_ca = root_ca
        self._pending_nonce: bytes | None = None
        self.jtag_unlocked = False

    def request_unlock(self) -> bytes:
        self.jtag_unlocked = False
        self._pending_nonce = secrets.token_bytes(32)
        return self._pending_nonce

    def submit_response(self, signature_envelope: Path) -> bool:
        if self._pending_nonce is None:
            return False
        with tempfile.TemporaryDirectory(prefix="jtag-nonce-") as temporary_directory:
            nonce_file = Path(temporary_directory) / "nonce.bin"
            nonce_file.write_bytes(self._pending_nonce)
            command = [sys.executable, str(VERIFIER), "--in", str(nonce_file), "--signature", str(signature_envelope)]
            if self.public_key:
                command.extend(("--public-key", str(self.public_key)))
            else:
                command.extend(("--root-ca", str(self.root_ca)))
            self.jtag_unlocked = subprocess.run(command, check=False).returncode == 0
        self._pending_nonce = None
        return self.jtag_unlocked