# Secure Signing Pipeline

An automotive-oriented reference pipeline that signs genuine upstream application artifacts
with either a raw OpenSSL key pair or a pinned-root PKI chain. It includes CMake integration
for `can-utils`, a reusable Bazel macro, Yocto layer metadata, and a simulated one-time
JTAG debug-authentication exchange.

Open the interactive [Secure Pipeline Console](docs/portal/index.html) to explore the trust
path, compare signing methods, step through JTAG authentication, and review the local
security assessment checks.

## Published documentation

GitHub Pages publishes the console after a push to `main` that changes `docs/portal`. In the
repository's **Settings → Pages**, select **GitHub Actions** as the source once. The published
site will be available at `https://vinodneelakantam.github.io/Secure_Signing_Pipeline/` after
the `Deploy documentation portal` workflow completes.

The checked-in upstream projects are Git submodules:

- `can-utils`: SocketCAN command-line tools, built and signed through CMake.
- `mosquitto`: MQTT broker daemon, packaged through Yocto metadata.
- `u-boot`: bootloader, intended to use its native FIT signing with the PKI hierarchy.
- `wireguard-linux-compat`: out-of-tree kernel module, paired with native module signing.

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

Run the security tests with `python3 -m unittest discover -s tests -v`.

## Security assessment

Run the repository-local adversarial checks with:

```bash
./pentest/run_security_checks.sh
```

This is an authorized test lane for this codebase only. It verifies that malformed signature
envelopes, method-downgrade attempts, signing-key substitution, untrusted PKI roots,
certificate/key mismatch, artifact tampering, and JTAG challenge replay are rejected.

## Security boundary

This is a reference implementation. Never commit private keys, never place them in a Yocto
image, and use an HSM or secure element for production signing. The C JTAG stub illustrates
the boot-ROM/secure-enclave API boundary; it is not a substitute for silicon debug
authentication fuses.