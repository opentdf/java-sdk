#!/usr/bin/env bash
#
# test-mlkem.sh — round-trip the Java SDK's pure ML-KEM key wrapping (FIPS 203)
# against a locally running OpenTDF platform.
#
# Per algorithm: encrypt → assert manifest → KAS rewrap → decrypt → diff.
# Wire format: ct(1088 or 1568) || AES-GCM(nonce(12) || DEK(32) || tag(16)),
# base64'd into keyAccess.wrappedKey. keyAccess.type stays "wrapped" (NOT
# "hybrid-wrapped" — pure ML-KEM reuses the existing wrapped slot; the KAS
# disambiguates by the registered key's algorithm).
#
# Prereqs:
#   * Local platform up at $PLATFORM_ENDPOINT on a branch with the ML-KEM PRs
#     applied (opentdf/platform PR 3491 server + key registration)
#   * preview.mlkem_enabled: true in opentdf-dev.yaml
#   * An mlkem:768 KAS key registered (and mlkem:1024 if you test 1024 — Go
#     KAS doesn't support 1024 yet at the time of writing)
#   * java, mvn (JDK 17), unzip, jq on PATH
#   * grpcurl optional (pre-flight key-publication check)
#
# Usage:
#   scripts/test-mlkem.sh                                  # 768 only (Go KAS scope)
#   scripts/test-mlkem.sh --algorithms MLKEM768Key,MLKEM1024Key   # both
#   scripts/test-mlkem.sh --skip-build                     # reuse existing jar
#   scripts/test-mlkem.sh --skip-kas-check                 # skip grpcurl pre-flight
#   PLATFORM_ENDPOINT=http://localhost:8080 scripts/test-mlkem.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
JAR="$REPO_ROOT/cmdline/target/cmdline.jar"

PLATFORM_ENDPOINT="${PLATFORM_ENDPOINT:-http://localhost:8080}"
KAS_URL="${KAS_URL:-$PLATFORM_ENDPOINT}"
CLIENT_ID="${CLIENT_ID:-opentdf-sdk}"
CLIENT_SECRET="${CLIENT_SECRET:-secret}"
DATA_ATTR="${DATA_ATTR:-https://example.com/attr/attr1/value/value1}"
# Default to 768 only because Go KAS hasn't shipped 1024 support yet.
ALGORITHMS=(MLKEM768Key)
SKIP_BUILD=0
SKIP_KAS_CHECK=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-build)        SKIP_BUILD=1; shift ;;
        --skip-kas-check)    SKIP_KAS_CHECK=1; shift ;;
        --algorithms)        IFS=, read -r -a ALGORITHMS <<< "$2"; shift 2 ;;
        --platform-endpoint) PLATFORM_ENDPOINT="$2"; shift 2 ;;
        --kas-url)           KAS_URL="$2"; shift 2 ;;
        --attr)              DATA_ATTR="$2"; shift 2 ;;
        --client-id)         CLIENT_ID="$2"; shift 2 ;;
        --client-secret)     CLIENT_SECRET="$2"; shift 2 ;;
        -h|--help)           sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)                   echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

# Map KeyType enum name → (algorithm string, ciphertext size, PEM marker).
# Function form (case statement) for bash 3.2 (macOS system bash) compat.
alg_to_string() {
    case "$1" in
        MLKEM768Key)  echo "mlkem:768" ;;
        MLKEM1024Key) echo "mlkem:1024" ;;
        *) return 1 ;;
    esac
}
ciphertext_size() {
    case "$1" in
        MLKEM768Key)  echo 1088 ;;
        MLKEM1024Key) echo 1568 ;;
        *) return 1 ;;
    esac
}

WORK_DIR="$(mktemp -d -t mlkem-pqc-XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

if [[ -t 1 ]]; then
    GREEN=$'\033[0;32m'; RED=$'\033[0;31m'; YELLOW=$'\033[0;33m'; RESET=$'\033[0m'
else
    GREEN=''; RED=''; YELLOW=''; RESET=''
fi
pass() { echo "${GREEN}[OK]${RESET}   $*"; }
fail() { echo "${RED}[FAIL]${RESET} $*"; }
info() { echo "${YELLOW}[..]${RESET}   $*"; }

require() { command -v "$1" >/dev/null 2>&1 || { fail "missing required tool: $1"; exit 2; }; }
require java; require unzip; require jq
[[ $SKIP_BUILD -eq 1 ]] || require mvn

run_cmdline() {
    java -jar "$JAR" \
        --client-id="$CLIENT_ID" \
        --client-secret="$CLIENT_SECRET" \
        --platform-endpoint="$PLATFORM_ENDPOINT" \
        -h "$@"
}

##### 1. Build
if [[ $SKIP_BUILD -eq 0 ]]; then
    info "Building cmdline (mvn clean install -DskipTests)"
    build_log="$WORK_DIR/build.log"
    if ! (cd "$REPO_ROOT" && mvn --batch-mode clean install -DskipTests) > "$build_log" 2>&1; then
        fail "Maven build failed. Tail of build log:"
        tail -40 "$build_log" | sed 's/^/    /'
        if grep -q "Buf API token" "$build_log" 2>/dev/null; then
            fail "Hint: run 'buf registry login' or export BUF_INPUT_HTTPS_USERNAME / BUF_INPUT_HTTPS_PASSWORD before retrying."
        fi
        exit 1
    fi
    pass "Build complete"
else
    info "Skipping build (--skip-build)"
fi
[[ -f "$JAR" ]] || { fail "jar not found at $JAR — run without --skip-build"; exit 1; }

##### 2. Pre-flight: confirm KAS publishes ML-KEM keys
if [[ $SKIP_KAS_CHECK -eq 0 ]] && command -v grpcurl >/dev/null 2>&1; then
    info "Pre-flight: querying KAS for ML-KEM public keys"
    host="${PLATFORM_ENDPOINT#http://}"; host="${host#https://}"
    for alg_name in "${ALGORITHMS[@]}"; do
        if ! alg=$(alg_to_string "$alg_name"); then
            fail "unknown algorithm: $alg_name"; exit 2
        fi
        resp=$(grpcurl -plaintext -d "{\"algorithm\":\"$alg\"}" \
                "$host" kas.AccessService/PublicKey 2>&1 || true)
        pem=$(jq -r '.publicKey // empty' <<<"$resp" 2>/dev/null || true)
        if [[ -z "$pem" ]]; then
            fail "$alg: KAS returned no publicKey. Response was:"
            echo "$resp" | head -5 | sed 's/^/    /'
            fail "Is the platform running with preview.mlkem_enabled=true and the key registered?"
            exit 1
        fi
        first_line=$(echo "$pem" | head -1)
        if [[ "$first_line" != *"ML-KEM"* ]]; then
            fail "$alg: KAS returned a non-ML-KEM PEM (first line: $first_line)"
            exit 1
        fi
        pass "$alg: KAS returns ML-KEM PEM ($first_line)"
    done
else
    info "Skipping KAS pre-flight check"
fi

##### 3. Round-trip each algorithm
PAYLOAD="$WORK_DIR/payload"
printf 'pure ml-kem round-trip payload @ %s\n' "$(date)" > "$PAYLOAD"
PAYLOAD_BYTES=$(wc -c < "$PAYLOAD" | tr -d ' ')
info "Test payload: $PAYLOAD_BYTES bytes"
echo "       --- plaintext ---"
sed 's/^/       /' < "$PAYLOAD"
echo "       --- end plaintext ---"

failures=()
for alg_name in "${ALGORITHMS[@]}"; do
    ct_size=$(ciphertext_size "$alg_name")
    # Expected wrappedKey decoded length: ct || nonce(12) || DEK(32) || tag(16)
    expected_wk_len=$((ct_size + 12 + 32 + 16))

    tdf="$WORK_DIR/test-${alg_name}.tdf"
    out="$WORK_DIR/out-${alg_name}"
    enc_log="$WORK_DIR/encrypt-${alg_name}.log"
    dec_log="$WORK_DIR/decrypt-${alg_name}.log"

    info "[$alg_name] encrypt"
    if ! run_cmdline encrypt \
            --kas-url="$KAS_URL" \
            --mime-type=text/plain \
            --attr="$DATA_ATTR" \
            --autoconfigure=false \
            --encap-key-type="$alg_name" \
            -f "$PAYLOAD" > "$tdf" 2> "$enc_log"; then
        fail "$alg_name: encrypt failed"
        sed 's/^/    /' < "$enc_log"
        failures+=("$alg_name (encrypt)")
        continue
    fi

    info "[$alg_name] verify manifest"
    manifest_entry=$(unzip -l "$tdf" 2>/dev/null | awk '/manifest\.json$/ {print $NF; exit}')
    if [[ -z "$manifest_entry" ]]; then
        fail "$alg_name: no manifest.json entry inside $tdf"
        failures+=("$alg_name (manifest entry missing)")
        continue
    fi
    manifest=$(unzip -p "$tdf" "$manifest_entry")
    # JSON key is "type" (Manifest.keyType is @SerializedName("type")).
    type=$(jq -r '.encryptionInformation.keyAccess[0].type' <<<"$manifest")
    ephem=$(jq -r '.encryptionInformation.keyAccess[0].ephemeralPublicKey // ""' <<<"$manifest")
    wrapped=$(jq -r '.encryptionInformation.keyAccess[0].wrappedKey // ""' <<<"$manifest")

    if [[ "$type" != "wrapped" ]]; then
        fail "$alg_name: type='$type' (expected 'wrapped' — ML-KEM reuses the RSA-wrapped slot)"
        echo "    keyAccess[0]:"
        jq '.encryptionInformation.keyAccess[0]' <<<"$manifest" 2>/dev/null | sed 's/^/      /'
        failures+=("$alg_name (bad type: $type)")
        continue
    fi
    if [[ -n "$ephem" ]]; then
        fail "$alg_name: ephemeralPublicKey unexpectedly set ('$ephem')"
        failures+=("$alg_name (stray ephemeralPublicKey)")
        continue
    fi
    if [[ -z "$wrapped" ]]; then
        fail "$alg_name: wrappedKey is empty"
        failures+=("$alg_name (empty wrappedKey)")
        continue
    fi
    actual_wk_len=$(base64 -d <<<"$wrapped" 2>/dev/null | wc -c | tr -d ' ')
    if [[ "$actual_wk_len" != "$expected_wk_len" ]]; then
        fail "$alg_name: wrappedKey decoded length $actual_wk_len != expected $expected_wk_len (ct=$ct_size + nonce(12) + DEK(32) + tag(16))"
        failures+=("$alg_name (bad wrappedKey length: $actual_wk_len)")
        continue
    fi
    pass "$alg_name: manifest OK (type=wrapped, length=$actual_wk_len, no ephemeralPublicKey)"
    echo "       --- keyAccess[0] (KAO) ---"
    jq '.encryptionInformation.keyAccess[0]' <<<"$manifest" | sed 's/^/       /'
    echo "       --- end keyAccess[0] ---"

    info "[$alg_name] decrypt (rewrap via KAS)"
    if ! run_cmdline decrypt -f "$tdf" > "$out" 2> "$dec_log"; then
        fail "$alg_name: decrypt failed"
        sed 's/^/    /' < "$dec_log"
        failures+=("$alg_name (decrypt)")
        continue
    fi
    if ! diff -q "$PAYLOAD" "$out" >/dev/null; then
        fail "$alg_name: decrypted payload differs from original"
        echo "    --- expected ---"
        head -c 200 "$PAYLOAD" | sed 's/^/    /'; echo
        echo "    --- got ---"
        head -c 200 "$out" | sed 's/^/    /'; echo
        failures+=("$alg_name (payload mismatch)")
        continue
    fi
    pass "$alg_name: round-trip OK"
    out_bytes=$(wc -c < "$out" | tr -d ' ')
    echo "       --- decrypted ($out_bytes bytes) ---"
    sed 's/^/       /' < "$out"
    echo "       --- end decrypted ---"
done

echo
if [[ ${#failures[@]} -eq 0 ]]; then
    echo "${GREEN}All ${#ALGORITHMS[@]} ML-KEM algorithm(s) passed round-trip.${RESET}"
    exit 0
else
    echo "${RED}FAILURES (${#failures[@]}):${RESET}"
    printf '  - %s\n' "${failures[@]}"
    exit 1
fi
