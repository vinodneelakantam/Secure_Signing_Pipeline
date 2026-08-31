SUMMARY = "Signed SocketCAN tools"
LICENSE = "GPL-2.0-only"
LIC_FILES_CHKSUM = "file://LICENSES/GPL-2.0-only.txt;md5=801f80980d171dd6425610833a22dbe6"
PV = "git"
EXTERNALSRC ?= "${TOPDIR}/../../third_party/can-utils"
inherit externalsrc cmake signing

do_install:append() {
    for binary in ${D}${bindir}/candump ${D}${bindir}/cansend ${D}${bindir}/cangen ${D}${bindir}/canfdtest; do
        [ -f "$binary" ] || continue
        secure_sign_file "$binary"
    done
}
FILES:${PN} += "${bindir}/*.sig"