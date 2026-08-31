#!/usr/bin/env python3
"""Generate a CycloneDX SBOM for this repository and its pinned upstream submodules."""

from __future__ import annotations

import argparse
import configparser
from pathlib import Path
import re
import subprocess

from cyclonedx.model import ExternalReference, ExternalReferenceType, XsUri
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.output.json import JsonV1Dot5
from packageurl import PackageURL

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
GITHUB_URL_PATTERN = re.compile(r"github\.com[:/](?P<owner>[^/]+)/(?P<name>[^/.]+)(?:\.git)?$")


def read_submodule_urls() -> dict[str, str]:
    parser = configparser.ConfigParser()
    parser.read(REPOSITORY_ROOT / ".gitmodules")
    urls: dict[str, str] = {}
    for section in parser.sections():
        path = parser.get(section, "path")
        urls[path] = parser.get(section, "url")
    return urls


def read_submodule_commits() -> dict[str, str]:
    result = subprocess.run(
        ["git", "submodule", "status"], cwd=REPOSITORY_ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
    )
    commits: dict[str, str] = {}
    for line in result.stdout.splitlines():
        stripped = line.strip().lstrip("-+U ")
        commit, path = stripped[:40], stripped.split()[1]
        commits[path] = commit
    return commits


def submodule_component(path: str, url: str, commit: str) -> Component:
    match = GITHUB_URL_PATTERN.search(url)
    purl = None
    if match:
        purl = PackageURL(type="github", namespace=match.group("owner"), name=match.group("name"), version=commit)
    return Component(
        type=ComponentType.APPLICATION,
        name=Path(path).name,
        version=commit,
        description=f"Pinned upstream source at {path}",
        purl=purl,
        external_references=[ExternalReference(type=ExternalReferenceType.VCS, url=XsUri(url))],
    )


def build_bom() -> Bom:
    bom = Bom()
    bom.metadata.component = Component(
        type=ComponentType.APPLICATION,
        name="secure-signing-pipeline",
        version="0.0.0-dev",
        description="Automotive Yocto secure signing and JTAG authentication reference pipeline",
    )
    urls = read_submodule_urls()
    commits = read_submodule_commits()
    for path, url in sorted(urls.items()):
        commit = commits.get(path, "unknown")
        component = submodule_component(path, url, commit)
        bom.components.add(component)
        bom.register_dependency(bom.metadata.component, [component])
    return bom


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=str(REPOSITORY_ROOT / "security" / "sbom" / "sbom.json"))
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    bom = build_bom()
    output_path = Path(arguments.out)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(JsonV1Dot5(bom).output_as_string(indent=2) + "\n", encoding="utf-8")
    print(f"Wrote SBOM with {len(bom.components)} tracked components to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
