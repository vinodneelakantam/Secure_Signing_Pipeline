SIGNING_METHOD ?= "pki"
SIGNING_PRIVATE_KEY ?= ""
SIGNING_CERT ?= ""
SIGNING_CHAIN ?= ""
SIGNING_TOOL ?= "${TOPDIR}/../signing/sign_artifact.py"

secure_sign_file() {
    artifact="$1"
    [ -n "${SIGNING_PRIVATE_KEY}" ] || bbfatal "SIGNING_PRIVATE_KEY must be supplied from protected build configuration"
    sign_args="--method ${SIGNING_METHOD} --key ${SIGNING_PRIVATE_KEY}"
    if [ "${SIGNING_METHOD}" = "pki" ]; then
        [ -n "${SIGNING_CERT}" ] && [ -n "${SIGNING_CHAIN}" ] || bbfatal "PKI signing requires SIGNING_CERT and SIGNING_CHAIN"
        sign_args="$sign_args --cert ${SIGNING_CERT} --chain ${SIGNING_CHAIN}"
    fi
    ${PYTHON_PN} ${SIGNING_TOOL} $sign_args --in "$artifact" --out "$artifact.sig"
}