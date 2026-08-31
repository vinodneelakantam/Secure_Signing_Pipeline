#!/usr/bin/env python3
"""Enforce the "never ship an unsigned binary" release gate.

Publishing an SBOM proves what is INSIDE a release. It says nothing about whether the
binaries were actually signed and that the signatures still verify. Treat those as two
separate, both-mandatory controls: a release is only approved when every artifact listed
as shippable has a signature envelope that verifies against the caller-supplied trust
material. Any missing, tampered, or unverifiable signature blocks the release.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
VERIFIER = REPOSITORY_ROOT / "signing" / "verify_artifact.py"


def evaluate_release(
    artifact_paths: list[Path], *, public_key: Path | None = None, root_ca: Path | None = None
) -> list[str]:
    """Return a list of human-readable failure reasons; an empty list means release-ready."""
    if (public_key is None) == (root_ca is None):
        return ["configure exactly one of --public-key or --root-ca"]

    failures: list[str] = []
    for artifact in artifact_paths:
        if not artifact.is_file():
            failures.append(f"{artifact}: artifact does not exist")
            continue
        signature = artifact.with_name(artifact.name + ".sig")
        if not signature.is_file():
            failures.append(f"{artifact.name}: BLOCKED - no signature envelope found ({signature.name} missing)")
            continue

        command = [sys.executable, str(VERIFIER), "--in", str(artifact), "--signature", str(signature)]
        command += ["--public-key", str(public_key)] if public_key else ["--root-ca", str(root_ca)]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if result.returncode != 0:
            detail = result.stdout.decode("utf-8", errors="replace").strip() or result.stderr.decode("utf-8", errors="replace").strip()
            failures.append(f"{artifact.name}: BLOCKED - signature does not verify ({detail})")
    return failures


def check_sbom_covers_artifacts(sbom_path: Path, artifact_names: list[str]) -> list[str]:
    """Warn (does not block) when the SBOM doesn't mention a release artifact by name."""
    try:
        sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"SBOM at {sbom_path} could not be parsed: {error}"]
    known = {component.get("name", "") for component in sbom.get("components", [])}
    known.add(sbom.get("metadata", {}).get("component", {}).get("name", ""))
    return [f"{name}: not referenced by any SBOM component (informational only)" for name in artifact_names if name not in known]


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", action="append", required=True, dest="artifacts", help="path to a release artifact; may be repeated")
    parser.add_argument("--public-key", help="trusted public key for openssl-signed artifacts")
    parser.add_argument("--root-ca", help="pinned Root CA PEM for pki-signed artifacts")
    parser.add_argument("--sbom", help="optional SBOM path to cross-reference artifact names against")
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    public_key = Path(arguments.public_key) if arguments.public_key else None
    root_ca = Path(arguments.root_ca) if arguments.root_ca else None
    artifact_paths = [Path(path) for path in arguments.artifacts]

    failures = evaluate_release(artifact_paths, public_key=public_key, root_ca=root_ca)
    warnings = check_sbom_covers_artifacts(Path(arguments.sbom), [path.name for path in artifact_paths]) if arguments.sbom else []

    for warning in warnings:
        print(f"WARN: {warning}")
    if failures:
        print("RELEASE BLOCKED:")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(f"RELEASE APPROVED: {len(artifact_paths)} artifact(s) signed and verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
