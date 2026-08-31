# Project Prompt: Secure Signing & JTAG Access Pipeline for Automotive Yocto Systems

Use this as the master prompt/spec to scaffold and implement the full project (in this repo,
in an AI coding session, or by hand). It consolidates all requirements gathered so far.

---

## 1. One-paragraph project brief

> Build an end-to-end **secure signing and debug-access pipeline** for an automotive,
> Yocto-based embedded Linux system. The pipeline must sign build artifacts (application
> binaries, kernel modules, and the final Yocto image) using **two interchangeable signing
> methods** — plain **OpenSSL key-pair signing** and a full **PKI (Root CA → Intermediate CA →
> Leaf/Signing cert)** chain — selectable via build parameters in **both CMake and Bazel**.
> The same asymmetric key material used for artifact signing must also be used to implement
> **secure JTAG debug-port access control** (challenge/response unlock), so that JTAG can only
> be enabled on hardware that trusts the same root of trust as the software. The target
> application built and signed by the pipeline must be a **real, well-known open-source
> project** (not a toy "hello world"), integrated as a **Git submodule**, and packaged through
> custom **Yocto layers**. Deliverables include architecture diagrams, CI automation, and
> verification tooling.

---

## 2. Target real-world applications (multiple, each exercising a different artifact type)

Don't sign a single toy binary — pull in **several real, well-known open-source projects**,
each as its own Git submodule, so the pipeline demonstrably signs the different kinds of
artifacts a real automotive Yocto build produces (userspace CLI tools, a background service,
a bootloader image, and a kernel module).

| Submodule | Upstream repo | Role in this project | Why it's a real fit |
|---|---|---|---|
| `third_party/can-utils` | [`linux-can/can-utils`](https://github.com/linux-can/can-utils) | Userspace CLI tools (`candump`, `cansend`, `cangen`, `canfdtest`) built via **CMake + Bazel**, each binary individually signed | SocketCAN is the standard automotive CAN bus interface on Linux; already has upstream Yocto recipes in `meta-openembedded` to compare against |
| `third_party/mosquitto` | [`eclipse/mosquitto`](https://github.com/eclipse/mosquitto) | Long-running MQTT broker **daemon**, signed and verified at systemd service start (signature-gated `ExecStartPre`) | Widely used in real IoT/automotive telemetry stacks; demonstrates signing a service binary, not just a CLI |
| `third_party/u-boot` | [`u-boot/u-boot`](https://github.com/u-boot/u-boot) | Bootloader; its native **FIT image** signing (`mkimage -F`, `CONFIG_FIT_SIGNATURE`) is reused/extended with our PKI hierarchy, and U-Boot is the natural place to root the **secure JTAG** unlock check before handing off to Linux | Real, widely deployed automotive/embedded bootloader; already has first-class OpenSSL-based image signing we integrate with rather than reinvent |
| `third_party/wireguard-linux-compat` | [`WireGuard/wireguard-linux-compat`](https://github.com/WireGuard/wireguard-linux-compat) | Single **out-of-tree kernel module**, built and signed with `scripts/sign-file` (standard Linux kernel module signing) plus our own detached `.sig`/PKI signature for cross-checking | Real, well-known kernel module; exercises Linux's built-in module-signing security feature (`CONFIG_MODULE_SIG`) alongside our pipeline |

Add them as real Git submodules:

```bash
git submodule add https://github.com/linux-can/can-utils.git third_party/can-utils
git submodule add https://github.com/eclipse/mosquitto.git third_party/mosquitto
git submodule add https://github.com/u-boot/u-boot.git third_party/u-boot
git submodule add https://github.com/WireGuard/wireguard-linux-compat.git third_party/wireguard-linux-compat
```

Treat `can-utils` as the primary/required target (used throughout CMake, Bazel, CI, and Yocto
sections below); `mosquitto`, `u-boot`, and `wireguard-linux-compat` are the additional
applications that round out the story to userspace-daemon, bootloader, and kernel-module
signing respectively. Do not fork any app's internal logic — only *add* `CMakeLists.txt` /
`BUILD.bazel` build definitions and a post-build/post-install signing step around each, so
upstream stays cleanly updatable via normal `git submodule update`.

---

## 3. Repository layout

```
Secure_Signing_Pipeline/
├── README.md
├── PROJECT_PROMPT.md
├── third_party/
│   ├── can-utils/                     # git submodule (unmodified upstream) - CLI tools
│   ├── mosquitto/                     # git submodule - MQTT broker daemon
│   ├── u-boot/                        # git submodule - bootloader, FIT image signing + JTAG gate
│   └── wireguard-linux-compat/        # git submodule - out-of-tree kernel module
├── signing/
│   ├── cmake/
│   │   └── Signing.cmake              # reusable CMake signing module
│   ├── bazel/
│   │   ├── signing.bzl                # custom Bazel rule/macro mirroring Signing.cmake
│   │   └── BUILD.bazel
│   ├── openssl/
│   │   ├── gen_openssl_keys.sh        # method 1: raw EC/RSA keypair
│   ├── pki/
│   │   ├── gen_ca_hierarchy.sh        # method 2: Root CA -> Intermediate -> Leaf
│   │   └── openssl-ca.cnf
│   ├── sign_artifact.py               # common signer CLI, used by CMake + Bazel + Yocto
│   └── verify_artifact.py             # common verifier CLI
├── jtag/
│   ├── openocd/
│   │   ├── secure_unlock.cfg          # OpenOCD config invoking challenge/response
│   │   └── target_stub.cfg
│   ├── jtag_authenticator.py          # host-side: signs device nonce with same keys
│   └── device_auth_stub/              # firmware-side reference: verifies signature, unlocks JTAG
│       └── jtag_auth.c
├── yocto/
│   ├── meta-secure-signing/
│   │   ├── classes/
│   │   │   └── image_sign.bbclass     # signs rootfs/kernel/modules at do_image_complete
│   │   ├── recipes-core/
│   │   │   └── signing-keys/
│   │   │       └── signing-keys.bb    # deploys public keys/certs into image (not private keys!)
│   │   └── conf/layer.conf
│   ├── meta-can-utils-secure/
│   │   ├── recipes-connectivity/
│   │   │   └── can-utils/
│   │   │       └── can-utils_git.bb   # builds submodule via CMake, signs each binary
│   │   └── conf/layer.conf
│   └── build/
│       └── conf/                      # local.conf / bblayers.conf templates, MACHINE=qemuarm64
├── ci/
│   └── github-actions/
│       └── secure-pipeline.yml        # builds CMake+Bazel, generates keys, signs, verifies, JTAG sim
├── docs/
│   ├── architecture.md
│   ├── diagrams/
│   │   ├── signing-flow.mmd           # mermaid sequence diagram
│   │   ├── jtag-unlock-flow.mmd
│   │   └── key-hierarchy.mmd
└── tests/
    ├── test_signing_roundtrip.py
    └── test_jtag_challenge_response.py
```

---

## 4. Signing subsystem

### 4.1 Method A — OpenSSL raw key-pair signing

- Generate an EC (prime256v1) or RSA-4096 keypair with plain `openssl`:
  ```bash
  openssl ecparam -name prime256v1 -genkey -noout -out signing_ec.key
  openssl ec -in signing_ec.key -pubout -out signing_ec.pub
  ```
- Sign artifact: `openssl dgst -sha256 -sign signing_ec.key -out artifact.sig artifact.bin`
- Verify: `openssl dgst -sha256 -verify signing_ec.pub -signature artifact.sig artifact.bin`
- Fast, no CA infra — good for local/dev builds and CI smoke tests.

### 4.2 Method B — PKI with CA hierarchy

- Root CA (offline, long-lived) → Intermediate/Signing CA (per release cycle) → Leaf signing
  cert used day-to-day. Model after real automotive/embedded secure-boot practice.
- Build with `openssl req` / `openssl ca` using `openssl-ca.cnf`, or reuse `easy-rsa`/`step-ca`
  if available.
- Signing produces a detached signature **plus** the leaf certificate (and chain) so a verifier
  only needs the Root CA public cert to validate trust, enabling key rotation without
  re-provisioning devices.
- Verify: validate cert chain to pinned root, then verify signature with the leaf cert's
  public key (`openssl smime -verify` or manual `dgst -verify` + chain check).

### 4.3 Common signer/verifier CLI

`signing/sign_artifact.py --method {openssl|pki} --key <path> [--cert <path> --chain <path>]
--in <artifact> --out <artifact>.sig`

This single script is invoked identically from CMake, Bazel, and the Yocto `image_sign.bbclass`,
so signing logic lives in exactly one place.

### 4.4 CMake integration (parameterized)

`signing/cmake/Signing.cmake` exposes a function:

```cmake
function(sign_target target)
  # SIGNING_METHOD: OPENSSL | PKI   (cache variable, default OPENSSL)
  # SIGNING_KEY, SIGNING_CERT, SIGNING_CHAIN as needed
  add_custom_command(TARGET ${target} POST_BUILD
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/signing/sign_artifact.py
            --method ${SIGNING_METHOD} --key ${SIGNING_KEY}
            $<$<STREQUAL:${SIGNING_METHOD},PKI>:--cert> $<$<STREQUAL:${SIGNING_METHOD},PKI>:${SIGNING_CERT}>
            --in $<TARGET_FILE:${target}> --out $<TARGET_FILE:${target}>.sig)
endfunction()
```

Root `CMakeLists.txt` for `can-utils` calls `sign_target(candump)`, `sign_target(cansend)`, etc.,
configurable at `cmake -DSIGNING_METHOD=PKI -DSIGNING_KEY=... -DSIGNING_CERT=... -DSIGNING_CHAIN=...`.

### 4.5 Bazel integration (parameterized)

`signing/bazel/signing.bzl` defines a `signed_binary` macro wrapping `cc_binary`:

```python
def signed_binary(name, signing_method = "openssl", key = None, cert = None, chain = None, **kwargs):
    native.cc_binary(name = name, **kwargs)
    native.genrule(
        name = name + "_sig",
        srcs = [":" + name] + ([key] if key else []) + ([cert] if cert else []),
        outs = [name + ".sig"],
        cmd = "python3 $(location //signing:sign_artifact) --method {} --key $(location {}) --in $(location :{}) --out $@".format(signing_method, key, name),
        tools = ["//signing:sign_artifact"],
    )
```

Selectable at the command line via `--define=signing_method=pki` or a `config_setting` +
`select()`, mirroring the CMake cache-variable ergonomics.

---

## 5. Secure JTAG using the same key material

Goal: JTAG debug port only unlocks for hosts that hold the private key trusted by the target
(same root of trust as software signing), so a stolen/leaked ECU can't be freely debugged.

**Flow (challenge/response, mirrors ARM CoreSight Debug Authentication / SWD-DAP lock concepts):**

1. Target boot ROM/firmware holds the **public key or leaf cert** (same PKI as artifact signing)
   fused/provisioned at manufacture; JTAG TAP is gated by default.
2. Debug host connects (OpenOCD) and requests unlock; target returns a random **nonce**.
3. Host signs the nonce with the **private signing key** (`jtag_authenticator.py`, reusing
   `sign_artifact.py`'s crypto core — same OpenSSL/PKI code path, method selectable).
4. Target verifies the signature against its embedded public key/cert (and chain, if PKI mode),
   and if valid, unlocks the JTAG TAP for a session (or asserts a debug-enable GPIO/register).
5. `device_auth_stub/jtag_auth.c` is a reference software model of step 4 for QEMU/simulation
   (since real silicon debug-authentication fuses aren't accessible in a demo); document clearly
   that in real silicon this logic lives in boot ROM / a secure enclave, not normal Linux
   userspace.

`jtag/openocd/secure_unlock.cfg` shows how this slots into a real OpenOCD workflow (pre-`init`
hook calling `jtag_authenticator.py`, only proceeding to `reset halt` on success).

---

## 6. Yocto layers

- **`meta-secure-signing`**: adds `image_sign.bbclass`, inherited by the image recipe, which
  signs the kernel Image, DTBs, kernel modules, and final rootfs/wic image using
  `sign_artifact.py` at `do_image_complete[postfuncs]`. Also has a `signing-keys` recipe that
  installs **public** keys/certs into `/etc/secure-signing/` on target (never ships private keys
  in the image).
- **`meta-can-utils-secure`**: a `can-utils_git.bb` recipe that points `SRC_URI` at the submodule
  (or mirrors it via `git://` with matching `SRCREV`), builds via the new CMake build
  (`inherit cmake`), and calls `sign_target` equivalents through a `do_compile:append` /
  `do_install:append` step so each installed binary gets a `.sig` alongside it.
- **`meta-mosquitto-secure`**: `mosquitto_git.bb` builds the broker daemon, signs the installed
  binary, and ships a `mosquitto-verify.service` systemd unit (`ExecStartPre=verify_artifact.py`)
  that refuses to start the broker if its signature doesn't check out.
- **`meta-uboot-secure`**: overrides/extends the standard `u-boot_%.bbappend` to build
  `third_party/u-boot` with `CONFIG_FIT_SIGNATURE` wired to our PKI leaf key, so the kernel
  FIT image is signed the same way as everything else, and embeds the JTAG-unlock public
  key/cert used by `jtag/device_auth_stub` into the U-Boot binary.
- **`meta-wireguard-secure`**: `wireguard-linux-compat_git.bb` builds the out-of-tree module
  against the target kernel, signs it with the kernel's own `scripts/sign-file` (so
  `CONFIG_MODULE_SIG_FORCE` accepts it) **and** produces our own detached `.sig`, demonstrating
  the two signing models side by side.
- `yocto/build/conf/local.conf.sample` sets `MACHINE = "qemuarm64"` (or a real automotive-ish
  BSP like `meta-raspberrypi` if physical JTAG testing is desired) and
  `SIGNING_METHOD = "pki"` as a distro/local config knob passed through to all the recipes
  above.

---

## 7. CI/CD (GitHub Actions)

`ci/github-actions/secure-pipeline.yml`:

1. Checkout with submodules (`submodules: recursive`).
2. Generate ephemeral OpenSSL keys and a throwaway PKI hierarchy (CI-only, never real prod keys).
3. Matrix build: `{build_system: [cmake, bazel], signing_method: [openssl, pki]}`.
4. Run `verify_artifact.py` on every produced `.sig` to prove round-trip correctness.
5. Run `tests/test_jtag_challenge_response.py` against the `device_auth_stub` simulator.
6. (Optional, slow job) Yocto build of `qemuarm64` image via `meta-secure-signing` +
   `meta-can-utils-secure`, then boot in QEMU and check signed binaries/certs exist on rootfs.
7. Upload signed artifacts + verification report as workflow artifacts.

---

## 8. Documentation & diagrams

- `docs/architecture.md`: overview + component diagram (Mermaid) tying together CMake/Bazel,
  the signing service, Yocto layers, and the JTAG authenticator.
- `docs/diagrams/signing-flow.mmd`: sequence diagram — build → sign_artifact.py → signature →
  verify_artifact.py — with both OpenSSL and PKI branches.
- `docs/diagrams/jtag-unlock-flow.mmd`: sequence diagram of the nonce/challenge-response unlock.
- `docs/diagrams/key-hierarchy.mmd`: Root CA → Intermediate CA → Leaf cert tree, and how the
  same leaf key is reused for artifact signing and JTAG authentication.

---

## 9. Testing & validation checklist

- [ ] `sign_artifact.py` / `verify_artifact.py` round-trip for both methods, including a
      **negative test** (tampered artifact must fail verification).
- [ ] CMake build produces `.sig` files next to each `can-utils` binary for both signing methods.
- [ ] Bazel build produces equivalent `.sig` outputs via `signed_binary` macro.
- [ ] PKI chain validation rejects a leaf cert not chained to the pinned root.
- [ ] JTAG simulator refuses unlock on bad/missing signature, unlocks on valid one.
- [ ] `mosquitto` fails to start via systemd when its `.sig` is tampered with or missing.
- [ ] `u-boot` FIT image built with a valid signature boots the kernel; a tampered FIT image
      is rejected by `CONFIG_FIT_SIGNATURE` verification.
- [ ] `wireguard-linux-compat` module loads under `CONFIG_MODULE_SIG_FORCE` with the kernel's
      own signature **and** independently verifies against our detached `.sig`.
- [ ] Yocto image boots in QEMU and contains public keys/certs but **no private keys**.
- [ ] CI pipeline green across the full `{cmake,bazel} x {openssl,pki}` matrix, and across all
      four submodule apps.

---

## 10. Security notes to respect throughout implementation

- Private keys never committed to the repo or baked into the Yocto image; CI generates
  ephemeral throwaway keys, real deployments load keys from an HSM/secure element.
- Use SHA-256+ digests, EC P-256 or RSA-3072+ — no MD5/SHA-1.
- Treat `device_auth_stub` explicitly as a **simulation** of boot-ROM/secure-enclave behavior,
  not production-grade secure hardware logic — call this out in `docs/architecture.md` so no one
  mistakes it for a real hardware root of trust.
- Validate all certificate chains against a pinned root; don't trust the system CA store.
