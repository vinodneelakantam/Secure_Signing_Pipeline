SUMMARY = "Signed MQTT broker"
LICENSE = "EPL-2.0"
LIC_FILES_CHKSUM = "file://LICENSE;md5=16f634c5a83a6c1e3d62f8c0f7e4bf93"
PV = "git"
EXTERNALSRC ?= "${TOPDIR}/../../third_party/mosquitto"
inherit externalsrc cmake signing

do_install:append() {
    secure_sign_file "${D}${sbindir}/mosquitto"
}
FILES:${PN} += "${sbindir}/mosquitto.sig"