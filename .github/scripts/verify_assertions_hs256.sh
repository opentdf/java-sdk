#!/usr/bin/env bash
set -euo pipefail

echo "hs256 assertions"
printf 'here is some data to encrypt' > data

HS256_KEY=$(openssl rand -base64 32)
SIGNED_ASSERTIONS_HS256='[{"id":"assertion1","type":"handling","scope":"tdo","appliesToState":"encrypted","statement":{"format":"json+stanag5636","schema":"urn:nato:stanag:5636:A:1:elements:json","value":"{\"ocl\":\"2024-10-21T20:47:36Z\"}"},"signingKey":{"alg":"HS256","key":"'"$HS256_KEY"'"}}]'
SIGNED_ASSERTION_VERIFICATON_HS256='{"keys":{"assertion1":{"alg":"HS256","key":"'"$HS256_KEY"'"}}}'

java -jar target/cmdline.jar \
  --client-id=opentdf-sdk \
  --client-secret=secret \
  --platform-endpoint=http://localhost:8080 \
  -h \
  encrypt \
  --kas-url=http://localhost:8080 \
  --mime-type=text/plain \
  --with-assertions="$SIGNED_ASSERTIONS_HS256" \
  --autoconfigure=false \
  -f data \
  -m 'here is some metadata' > test.tdf

java -jar target/cmdline.jar \
  --client-id=opentdf-sdk \
  --client-secret=secret \
  --platform-endpoint=http://localhost:8080 \
  -h \
  decrypt \
  --with-assertion-verification-keys="$SIGNED_ASSERTION_VERIFICATON_HS256" \
  -f test.tdf > decrypted

if ! diff -q data decrypted; then
  printf 'decrypted data is incorrect [%s]\n' "$(< decrypted)"
  exit 1
fi
