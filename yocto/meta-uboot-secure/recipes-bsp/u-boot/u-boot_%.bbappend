EXTERNALSRC ?= "${TOPDIR}/../../third_party/u-boot"
inherit externalsrc
UBOOT_FIT_SIGNATURE ?= "1"
# Configure U-Boot's CONFIG_FIT_SIGNATURE and key DTB in the BSP-specific defconfig.