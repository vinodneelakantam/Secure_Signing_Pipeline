# Embedded DevOps checklist: SBOM vulnerability checks and the "no unsigned binaries" gate

This is written for the case study this repository demonstrates: an SBOM was published
without anyone actually re-verifying that the binaries it describes were signed. An SBOM
tells you **what is inside** a release. It says nothing about whether that release is
**trustworthy**. Treat those as two separate, both-mandatory controls.

## 1. Static vulnerability check on the SBOM (SCA)

Run: `./security/sca/run_sca.sh`

- [ ] Generate a fresh SBOM before every scan (`python3 security/sbom/generate_sbom.py`) —
      a stale SBOM produces a stale, meaningless scan.
- [ ] Scan **pinned Python/build tooling** (`security/requirements.txt`) against a real
      advisory database (this repo uses OSV-Scanner against OSV.dev). This is real
      ecosystem SCA: package name + version -> known CVEs/GHSAs.
- [ ] Do **not** assume the same tool gives you coverage for **vendored C/C++ submodules
      pinned by commit SHA** (`can-utils`, `mosquitto`, `u-boot`, `wireguard-linux-compat`).
      Ecosystem SCA keys advisories by package + semver range; a `pkg:github/...@<commit>`
      PURL usually will not resolve to anything, which is exactly what
      `security/sca/run_sca.sh` shows you happening against `security/sbom/sbom.json`.
- [ ] For vendored/submodule components, track advisories manually against the upstream
      project's own security advisories/CVE feed for the specific pinned commit or the
      nearest tagged release, on a cadence (not just once at integration time).
- [ ] Use a **lockfile**, not loose top-level pins. A resolver is free to pick the oldest
      version that satisfies a loose constraint (`cyclonedx-bom==7.3.1` alone let a
      dependency resolver select vulnerable `idna` and `lxml` transitive versions in this
      repo's own SCA run). Pin transitive dependencies to their minimum patched version, or
      generate a full lock and re-scan it.
- [ ] Triage by severity. This repo's CI treats any finding against
      `security/requirements.txt` as a hard failure (`security-scans.yml`); decide your own
      Critical/High bar and gate on it, don't just log it.
- [ ] Re-run the scan after every dependency bump AND on a schedule (advisories are
      published continuously; a clean scan today is not a clean scan next month).

## 2. Never ship a binary without a verified signature

Run: `python3 security/release-gate/check_release_gate.py --artifact <path> --public-key
<key>` (or `--root-ca <cert>` for PKI mode) for every artifact in a release.

- [ ] Every artifact that ships has an adjacent signature envelope (`<artifact>.sig`).
      Missing envelope = **blocked**, not a warning.
- [ ] The signature is **re-verified programmatically at release time**, not assumed valid
      because it was signed earlier in the pipeline. Compromise, corruption, or a
      copy-paste mistake between build and release can silently drop or invalidate it.
- [ ] The verification uses the **pinned trust root** (public key or Root CA) that release
      engineering controls — never a key bundled with the artifact itself.
- [ ] Publishing/sharing an SBOM is **not** a substitute for this check. An SBOM can be
      generated and shared correctly while the binaries it describes are unsigned,
      re-signed with the wrong key, or tampered with after signing — the SBOM's JSON has
      no cryptographic link to the actual shipped bytes unless you build that link
      yourself (this is the exact class of incident this checklist exists to prevent).
- [ ] The check is **automated and fails closed** in CI/CD (`security/release-gate/`), not
      a step in a human release runbook that can be skipped under deadline pressure.
- [ ] The gate is fuzz-tested against adversarial input, not just the happy path — see
      `security/dast/fuzz_release_gate.py`, which asserts the gate blocks every one of:
      missing signature, tampered artifact after signing, wrong signing key, and a
      corrupted signature envelope, across randomized scenarios.

## 3. Suggested CI ordering

1. Build artifacts (CMake/Bazel/Yocto).
2. Generate SBOM.
3. Run SCA against the SBOM and pinned tooling dependencies (`security/sca/run_sca.sh`).
4. Sign artifacts.
5. Run the release gate against the signed artifacts (`security/release-gate/`).
6. Only if 3 and 5 both pass: publish the SBOM and the signed artifacts together, as one
   release, from one pipeline run — never assembled by hand from separate steps.
