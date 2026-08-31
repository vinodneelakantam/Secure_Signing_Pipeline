# Secure Signing Pipeline

An automotive-oriented reference pipeline that signs genuine upstream application artifacts
with either a raw OpenSSL key pair or a pinned-root PKI chain. It includes CMake and Bazel
integration for `can-utils`, Yocto layer metadata for four real applications, a simulated
one-time JTAG debug-authentication exchange, an interactive documentation portal, and
embedded-focused SBOM/SAST/DAST tooling.

See [PROJECT_PROMPT.md](PROJECT_PROMPT.md) for the full design specification this repository
implements.

Open the interactive [ECU Security Range](docs/portal/index.html) — a game-style simulation
console with a mission rail (Briefing, Signing Bay, JTAG Range, Red Team Ops), a live mission
console log, and a trust-score/objective system, all wired to the same accurate technical
content: trust path, signing methods, JTAG challenge-response, and the security assessment
checks.

## Published documentation

GitHub Pages publishes the console after a push to `main` that changes `docs/portal`. In the
repository's **Settings → Pages**, select **GitHub Actions** as the source once. The published
site will be available at `https://vinodneelakantam.github.io/Secure_Signing_Pipeline/` after
the `Deploy documentation portal` workflow completes.

The checked-in upstream projects are Git submodules under `third_party/`:

- `can-utils`: SocketCAN command-line tools, built and signed through CMake and Bazel.
- `mosquitto`: MQTT broker daemon, packaged through Yocto metadata.
- `u-boot`: bootloader, intended to use its native FIT signing with the PKI hierarchy.
- `wireguard-linux-compat`: out-of-tree kernel module, paired with native module signing.

## Repository layout

| Path | Contents |
|---|---|
| `signing/` | Shared `sign_artifact.py` / `verify_artifact.py` CLIs, `encrypt_artifact.py` / `decrypt_artifact.py` (AES-256-CBC + HMAC-SHA256), OpenSSL/PKI/AES key generators, CMake module, Bazel macro |
| `jtag/` | Host challenge signer, device challenge/response simulator, OpenOCD config stubs, C boot-ROM reference stub |
| `yocto/` | `meta-secure-signing`, `meta-can-utils-secure`, `meta-mosquitto-secure`, `meta-uboot-secure`, `meta-wireguard-secure` layers |
| `docs/portal/` | Static interactive documentation console (published via GitHub Pages) |
| `pentest/` | Authorized repository-local adversarial test runner |
| `security/` | SBOM generator, SAST runner, DAST fuzz harness |
| `tests/` | Signing round-trip, JTAG challenge-response, and adversarial security tests |
| `third_party/` | Pinned upstream application submodules |

## Quick start

Initialize sources and generate **development-only** key material outside the repository:

```bash
git submodule update --init --recursive
./signing/openssl/gen_openssl_keys.sh /tmp/secure-signing-keys
cmake -S . -B build -DENABLE_ARTIFACT_SIGNING=ON \
	-DSIGNING_METHOD=openssl \
	-DSIGNING_KEY=/tmp/secure-signing-keys/signing.key
cmake --build build
python3 signing/verify_artifact.py \
	--in build/third_party/can-utils/candump \
	--signature build/third_party/can-utils/candump.sig \
	--public-key /tmp/secure-signing-keys/signing.pub
```

For PKI mode, create a Root CA, Intermediate CA, and leaf signer:

```bash
./signing/pki/gen_ca_hierarchy.sh /tmp/secure-signing-pki
cmake -S . -B build-pki -DENABLE_ARTIFACT_SIGNING=ON \
	-DSIGNING_METHOD=pki \
	-DSIGNING_KEY=/tmp/secure-signing-pki/leaf.key \
	-DSIGNING_CERT=/tmp/secure-signing-pki/leaf.pem \
	-DSIGNING_CHAIN=/tmp/secure-signing-pki/intermediate.pem
cmake --build build-pki
python3 signing/verify_artifact.py \
	--in build-pki/third_party/can-utils/candump \
	--signature build-pki/third_party/can-utils/candump.sig \
	--root-ca /tmp/secure-signing-pki/root.pem
```

Bazel builds use the same signer through the `signed_binary` macro in `signing/bazel/signing.bzl`,
which wraps `cc_binary` and emits a `<name>.sig` envelope using the chosen `signing_method`.

Signing proves integrity/authenticity but leaves content readable. For artifacts that must
also stay confidential (e.g. proprietary calibration data), use the AES-256 companion:

```bash
./signing/aes/gen_confidentiality_key.sh /tmp/secure-signing-aes
python3 signing/encrypt_artifact.py --key /tmp/secure-signing-aes/confidentiality.key \
	--in calibration.bin --out calibration.bin.enc
python3 signing/decrypt_artifact.py --key /tmp/secure-signing-aes/confidentiality.key \
	--envelope calibration.bin.enc --out calibration.bin.recovered
```

Uses AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC), since OpenSSL's `enc` CLI does not support
AEAD ciphers (`enc: AEAD ciphers not supported`); the HMAC tag is checked in constant time
before any decryption is attempted. Recommended order: encrypt first, then sign the `.enc`
envelope with `sign_artifact.py` so the signature also covers the exact ciphertext shipped.

Run the security tests with `python3 -m unittest discover -s tests -v`.

## Security assessment

Run the repository-local adversarial checks with:

```bash
./pentest/run_security_checks.sh
```

This is an authorized test lane for this codebase only. It verifies that malformed signature
envelopes, method-downgrade attempts, signing-key substitution, untrusted PKI roots,
certificate/key mismatch, artifact tampering, and JTAG challenge replay are rejected.

## Embedded DevSecOps tooling

`security/` adds three practices commonly required for embedded/automotive supply-chain
security. All three run in CI on every push via `.github/workflows/security-scans.yml`.

**SBOM** — CycloneDX bill of materials for this repository and its pinned upstream sources:

```bash
pip install -r security/requirements.txt
python3 security/sbom/generate_sbom.py
```

Produces `security/sbom/sbom.json`, listing `can-utils`, `mosquitto`, `u-boot`, and
`wireguard-linux-compat` as components with `pkg:github/...` PURLs pinned to the exact
submodule commit, so every build is traceable to precise upstream revisions.

**SAST** — static analysis of repository-owned code (submodule sources are not scanned):

```bash
./security/sast/run_sast.sh
```

Runs Bandit against the Python signing/JTAG/test tooling and cppcheck against the C
JTAG authentication stub, failing on medium-or-higher severity findings.

**DAST** — dynamic fuzz testing of the running verifier process boundary:

```bash
python3 security/dast/fuzz_verify_artifact.py --iterations 300
```

Feeds randomized artifacts, envelopes, and trust-material paths into the actual
`verify_artifact.py` process and asserts it always fails closed (exit 0 or 1) and never
crashes or hangs. This targets only this repository's own tooling, not external systems.
A second fuzz harness, `python3 security/dast/fuzz_release_gate.py --iterations 300`,
does the same for the release gate below (missing/tampered/wrong-key/corrupted signatures).

**SCA** — static vulnerability check against the SBOM and pinned tooling:

```bash
./security/sca/run_sca.sh
```

Downloads a pinned OSV-Scanner release and checks `security/requirements.txt` against
real OSV.dev advisories (this repo's own CI run has already caught and fixed a real
transitive `lxml`/`idna` CVE this way). It also runs against `security/sbom/sbom.json` to
show, honestly, that ecosystem SCA tools generally **cannot** resolve vulnerabilities for
`pkg:github` submodule PURLs pinned by commit SHA — see the checklist below for how to
close that gap.

**Release gate** — the "never ship an unsigned binary" control:

```bash
python3 security/release-gate/check_release_gate.py \
  --artifact build/third_party/can-utils/candump \
  --public-key /tmp/secure-signing-keys/signing.pub \
  --sbom security/sbom/sbom.json
```

Fails closed (exit 1) if any listed artifact is missing its `.sig` envelope or the
envelope doesn't verify. Publishing an SBOM is not a substitute for this check — it
describes what's inside a release, not whether it's trustworthy. Full checklist:
[security/release-gate/CHECKLIST.md](security/release-gate/CHECKLIST.md).

## Continuous integration

Three workflows run under `.github/workflows/`:

- `secure-pipeline.yml`: builds signed `can-utils` binaries across the OpenSSL/PKI matrix and
  runs the signing/JTAG test suite.
- `security-scans.yml`: generates the SBOM, runs SAST, and runs the DAST fuzz harness.
- `deploy-docs.yml`: publishes `docs/portal` to GitHub Pages on pushes to `main`.

## Security boundary

This is a reference implementation. Never commit private keys, never place them in a Yocto
image, and use an HSM or secure element for production signing. The C JTAG stub illustrates
the boot-ROM/secure-enclave API boundary; it is not a substitute for silicon debug
authentication fuses.