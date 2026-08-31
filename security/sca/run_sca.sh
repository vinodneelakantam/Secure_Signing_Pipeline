#!/usr/bin/env sh
# Software Composition Analysis: static vulnerability scan of pinned dependencies.
#
# Two things get scanned, and they are NOT the same kind of check:
#  1. security/requirements.txt  - real PyPI packages -> real OSV.dev advisory lookup.
#  2. security/sbom/sbom.json    - vendored git submodules pinned by commit SHA.
#     OSV (and most ecosystem SCA tools) key their advisories by package + semver
#     range, not by arbitrary commit hashes of a vendored source tree, so this step
#     intentionally runs anyway to show that "No package sources found" result: a
#     CycloneDX SBOM alone does not give you submodule vulnerability coverage. See
#     security/release-gate/CHECKLIST.md item 2 for how to close that gap.
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repository_root"

OSV_SCANNER_VERSION="v2.5.1"
OSV_SCANNER_BIN="${OSV_SCANNER_BIN:-$repository_root/.tools/osv-scanner}"

if [ ! -x "$OSV_SCANNER_BIN" ]; then
    mkdir -p "$(dirname "$OSV_SCANNER_BIN")"
    echo "Fetching osv-scanner ${OSV_SCANNER_VERSION}..."
    curl -sSfL -o "$OSV_SCANNER_BIN" \
        "https://github.com/google/osv-scanner/releases/download/${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64"
    chmod +x "$OSV_SCANNER_BIN"
fi

status=0

echo "== SCA: security/requirements.txt (PyPI ecosystem, real advisory lookup) =="
"$OSV_SCANNER_BIN" scan source --lockfile=security/requirements.txt --format table || status=1

echo
echo "== SCA: security/sbom/sbom.json (vendored submodules pinned by commit) =="
echo "Expect 'No package sources found': pkg:github PURLs are source pins, not"
echo "published package versions, so ecosystem SCA cannot resolve them to advisories."
"$OSV_SCANNER_BIN" scan source --format table security/sbom/sbom.json || true

if [ "$status" -ne 0 ]; then
    echo
    echo "SCA FAILED: known vulnerabilities found in pinned Python tooling dependencies."
fi
exit "$status"
