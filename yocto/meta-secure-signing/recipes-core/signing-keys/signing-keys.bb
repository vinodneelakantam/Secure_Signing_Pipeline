SUMMARY = "Pinned public root certificate for secure signing verification"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"
SIGNING_ROOT_CERT ?= ""

do_install() {
    [ -n "${SIGNING_ROOT_CERT}" ] || bbfatal "SIGNING_ROOT_CERT must name a public root certificate"
    install -d ${D}${sysconfdir}/secure-signing
    install -m 0644 ${SIGNING_ROOT_CERT} ${D}${sysconfdir}/secure-signing/root-ca.pem
}

FILES:${PN} = "${sysconfdir}/secure-signing/root-ca.pem"