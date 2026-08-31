SUMMARY = "Signed WireGuard out-of-tree kernel module"
LICENSE = "GPL-2.0-only"
PV = "git"
EXTERNALSRC ?= "${TOPDIR}/../../third_party/wireguard-linux-compat"
inherit externalsrc module signing

do_install:append() {
    for module in $(find ${D} -name '*.ko'); do
        secure_sign_file "$module"
    done
}
FILES:${PN} += "${nonarch_base_libdir}/modules/**/*.sig"