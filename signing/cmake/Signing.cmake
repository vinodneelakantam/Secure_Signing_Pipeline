function(sign_target target signature_directory)
  if(NOT TARGET ${target})
    message(FATAL_ERROR "Cannot sign unknown target: ${target}")
  endif()
  if(NOT SIGNING_KEY)
    message(FATAL_ERROR "SIGNING_KEY is required when ENABLE_ARTIFACT_SIGNING is ON")
  endif()
  if(NOT SIGNING_METHOD STREQUAL "openssl" AND NOT SIGNING_METHOD STREQUAL "pki")
    message(FATAL_ERROR "SIGNING_METHOD must be openssl or pki")
  endif()
  if(SIGNING_METHOD STREQUAL "pki" AND (NOT SIGNING_CERT OR NOT SIGNING_CHAIN))
    message(FATAL_ERROR "PKI signing requires SIGNING_CERT and SIGNING_CHAIN")
  endif()

  set(signing_arguments --method ${SIGNING_METHOD} --key ${SIGNING_KEY})
  if(SIGNING_METHOD STREQUAL "pki")
    list(APPEND signing_arguments --cert ${SIGNING_CERT} --chain ${SIGNING_CHAIN})
  endif()
  set(signature_file ${signature_directory}/${target}.sig)
  add_custom_command(OUTPUT ${signature_file}
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/signing/sign_artifact.py
      ${signing_arguments}
      --in $<TARGET_FILE:${target}> --out ${signature_file}
    DEPENDS ${target} ${CMAKE_SOURCE_DIR}/signing/sign_artifact.py ${SIGNING_KEY}
    VERBATIM
    COMMENT "Signing ${target} with ${SIGNING_METHOD}")
  add_custom_target(${target}_signature ALL DEPENDS ${signature_file})
endfunction()