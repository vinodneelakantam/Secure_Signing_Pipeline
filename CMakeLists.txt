cmake_minimum_required(VERSION 3.24)

project(secure_signing_pipeline LANGUAGES C)

option(ENABLE_ARTIFACT_SIGNING "Generate detached signatures for selected can-utils binaries" OFF)
set(SIGNING_METHOD "openssl" CACHE STRING "Signature method: openssl or pki")
set_property(CACHE SIGNING_METHOD PROPERTY STRINGS openssl pki)
set(SIGNING_KEY "" CACHE FILEPATH "Private key used only at build time")
set(SIGNING_CERT "" CACHE FILEPATH "Leaf certificate PEM for PKI mode")
set(SIGNING_CHAIN "" CACHE FILEPATH "Intermediate certificate chain PEM for PKI mode")

add_subdirectory(third_party/can-utils)

if(ENABLE_ARTIFACT_SIGNING)
  find_package(Python3 REQUIRED COMPONENTS Interpreter)
  include(signing/cmake/Signing.cmake)
  foreach(target candump cansend cangen canfdtest)
    if(TARGET ${target})
      sign_target(${target} ${CMAKE_BINARY_DIR}/third_party/can-utils)
    endif()
  endforeach()
endif()