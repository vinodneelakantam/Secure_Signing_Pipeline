inherit signing

secure_sign_image_artifacts() {
    for artifact in ${IMGDEPLOYDIR}/${IMAGE_NAME}*.wic ${DEPLOY_DIR_IMAGE}/${KERNEL_IMAGETYPE}; do
        [ -f "$artifact" ] || continue
        secure_sign_file "$artifact"
    done
}
do_image_complete[postfuncs] += "secure_sign_image_artifacts"