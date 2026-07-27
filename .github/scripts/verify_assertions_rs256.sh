#!/usr/bin/env bash
set -euo pipefail

echo "rs256 assertions"
printf 'here is some data to encrypt' > data

openssl genpkey -algorithm RSA -out rs_private_key.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in rs_private_key.pem -out rs_public_key.pem

RS256_PRIVATE_KEY=$(awk '{printf "%s\\n", $0}' rs_private_key.pem)
RS256_PUBLIC_KEY=$(awk '{printf "%s\\n", $0}' rs_public_key.pem)
SIGNED_ASSERTIONS_RS256='[{"id":"assertion1","type":"handling","scope":"tdo","appliesToState":"encrypted","statement":{"format":"json+stanag5636","schema":"urn:nato:stanag:5636:A:1:elements:json","value":"{\"ocl\":\"2024-10-21T20:47:36Z\"}"},"signingKey":{"alg":"RS256","key":"'"$RS256_PRIVATE_KEY"'"}}]'
SIGNED_ASSERTION_VERIFICATON_RS256='{"keys":{"assertion1":{"alg":"RS256","key":"'"$RS256_PUBLIC_KEY"'"}}}'

java -jar target/cmdline.jar \
  --client-id=opentdf-sdk \
  --client-secret=secret \
  --platform-endpoint=http://localhost:8080 \
  -h \
  encrypt \
  --kas-url=http://localhost:8080 \
  --mime-type=text/plain \
  --with-assertions "$SIGNED_ASSERTIONS_RS256" \
  --autoconfigure=false \
  -f data \
  -m 'here is some metadata' > test.tdf

java -jar target/cmdline.jar \
  --client-id=opentdf-sdk \
  --client-secret=secret \
  --platform-endpoint=http://localhost:8080 \
  -h \
  decrypt \
  --with-assertion-verification-keys "$SIGNED_ASSERTION_VERIFICATON_RS256" \
  -f test.tdf > decrypted

if ! diff -q data decrypted; then
  printf 'decrypted data is incorrect [%s]\n' "$(< decrypted)"
  exit 1
fi

