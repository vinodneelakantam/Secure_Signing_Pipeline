#!/usr/bin/env sh
set -eu

output_directory=${1:?usage: gen_openssl_keys.sh OUTPUT_DIRECTORY}
umask 077
mkdir -p "$output_directory"
openssl ecparam -name prime256v1 -genkey -noout -out "$output_directory/signing.key"
openssl ec -in "$output_directory/signing.key" -pubout -out "$output_directory/signing.pub"
printf '%s\n' "Generated development signing key pair in $output_directory"