#!/usr/bin/env sh
set -eu

output_directory=${1:?usage: gen_confidentiality_key.sh OUTPUT_DIRECTORY}
umask 077
mkdir -p "$output_directory"
# 64 raw bytes: first 32 = AES-256 key, last 32 = HMAC-SHA256 key (Encrypt-then-MAC).
openssl rand -out "$output_directory/confidentiality.key" 64
printf '%s\n' "Generated development AES-256 + HMAC-SHA256 confidentiality key in $output_directory"
