#!/usr/bin/env bash
set -euo pipefail

printf 'here is some data to encrypt' > data

java -jar target/cmdline.jar \
  --client-id=opentdf-sdk \
  --client-secret=secret \
  --platform-endpoint=http://localhost:8080 \
  -h \
  encrypt \
  --kas-url=http://localhost:8080 \
  --mime-type=text/plain \
  --attr https://example.com/attr/attr1/value/value1 \
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

java -jar target/cmdline.jar \
  --client-id=opentdf-sdk \
  --client-secret=secret \
  --platform-endpoint=http://localhost:8080 \
  -h \
  metadata \
  -f test.tdf > metadata

if ! diff -q data decrypted; then
  printf 'decrypted data is incorrect [%s]\n' "$(< decrypted)"
  exit 1
fi

if [ "$(< metadata)" != 'here is some metadata' ]; then
  printf 'metadata is incorrect [%s]\n' "$(< metadata)"
  exit 1
fi

