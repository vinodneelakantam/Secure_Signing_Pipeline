#!/usr/bin/env sh
set -eu

output_directory=${1:?usage: gen_ca_hierarchy.sh OUTPUT_DIRECTORY}
umask 077
mkdir -p "$output_directory"
extensions="$output_directory/extensions.cnf"
cat > "$extensions" <<'EOF'
[intermediate_ca]
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
[leaf]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
EOF

openssl ecparam -name prime256v1 -genkey -noout -out "$output_directory/root.key"
openssl req -x509 -new -key "$output_directory/root.key" -sha256 -days 3650 -subj '/CN=Secure Signing Development Root' -out "$output_directory/root.pem"
openssl ecparam -name prime256v1 -genkey -noout -out "$output_directory/intermediate.key"
openssl req -new -key "$output_directory/intermediate.key" -subj '/CN=Secure Signing Development Intermediate' -out "$output_directory/intermediate.csr"
openssl x509 -req -in "$output_directory/intermediate.csr" -CA "$output_directory/root.pem" -CAkey "$output_directory/root.key" -CAcreateserial -days 1825 -sha256 -extfile "$extensions" -extensions intermediate_ca -out "$output_directory/intermediate.pem"
openssl ecparam -name prime256v1 -genkey -noout -out "$output_directory/leaf.key"
openssl req -new -key "$output_directory/leaf.key" -subj '/CN=Secure Signing Development Leaf' -out "$output_directory/leaf.csr"
openssl x509 -req -in "$output_directory/leaf.csr" -CA "$output_directory/intermediate.pem" -CAkey "$output_directory/intermediate.key" -CAcreateserial -days 365 -sha256 -extfile "$extensions" -extensions leaf -out "$output_directory/leaf.pem"
printf '%s\n' "Generated development PKI hierarchy in $output_directory"