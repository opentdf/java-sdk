#!/usr/bin/env bash
set -euo pipefail

echo "basic assertions"
printf 'here is some data to encrypt' > data

ASSERTIONS='[{"id":"assertion1","type":"handling","scope":"tdo","appliesToState":"encrypted","statement":{"format":"json+stanag5636","schema":"urn:nato:stanag:5636:A:1:elements:json","value":"{\"ocl\":\"2024-10-21T20:47:36Z\"}"}}]'

java -jar target/cmdline.jar \
  --client-id=opentdf-sdk \
  --client-secret=secret \
  --platform-endpoint=http://localhost:8080 \
  -h \
  encrypt \
  --kas-url=http://localhost:8080 \
  --mime-type=text/plain \
  --with-assertions="$ASSERTIONS" \
  --autoconfigure=false \
  -f data \
  -m 'here is some metadata' > test.tdf

java -jar target/cmdline.jar \
  --client-id=opentdf-sdk \
  --client-secret=secret \
  --platform-endpoint=http://localhost:8080 \
  -h \
  decrypt \
  -f test.tdf > decrypted

if ! diff -q data decrypted; then
  printf 'decrypted data is incorrect [%s]\n' "$(< decrypted)"
  exit 1
fi

