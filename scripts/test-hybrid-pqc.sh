#!/usr/bin/env bash
#
# test-hybrid-pqc.sh — round-trip the Java SDK's hybrid post-quantum key
# wrapping against a locally running OpenTDF platform.
#
# Per algorithm: encrypt → assert manifest → KAS rewrap → decrypt → diff.
#
# Prereqs:
#   * Local platform up at $PLATFORM_ENDPOINT with hybrid KAS keys registered
#     for hpqt:xwing, hpqt:secp256r1-mlkem768, hpqt:secp384r1-mlkem1024
#   * java, mvn (JDK 17), unzip, jq on PATH
#   * grpcurl optional (used only for the pre-flight key-publication check)
#
# Usage:
#   scripts/test-hybrid-pqc.sh                                    # full run, all 3 algorithms
#   scripts/test-hybrid-pqc.sh --skip-build                       # reuse existing jar
#   scripts/test-hybrid-pqc.sh --skip-kas-check                   # skip grpcurl pre-flight
#   scripts/test-hybrid-pqc.sh --algorithms HybridXWingKey        # subset
#   PLATFORM_ENDPOINT=http://localhost:8080 scripts/test-hybrid-pqc.sh
#
# See scripts/README.md for a full prereq + troubleshooting guide.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
JAR="$REPO_ROOT/cmdline/target/cmdline.jar"

PLATFORM_ENDPOINT="${PLATFORM_ENDPOINT:-http://localhost:8080}"
KAS_URL="${KAS_URL:-$PLATFORM_ENDPOINT}"
CLIENT_ID="${CLIENT_ID:-opentdf-sdk}"
CLIENT_SECRET="${CLIENT_SECRET:-secret}"
DATA_ATTR="${DATA_ATTR:-https://example.com/attr/attr1/value/value1}"
ALGORITHMS=(HybridXWingKey HybridSecp256r1MLKEM768Key HybridSecp384r1MLKEM1024Key)
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

# Map KeyType enum name → the hpqt:* algorithm string the KAS expects.
# Function form (instead of `declare -A`) so this works on macOS bash 3.2.
alg_to_string() {
    case "$1" in
        HybridXWingKey)              echo "hpqt:xwing" ;;
        HybridSecp256r1MLKEM768Key)  echo "hpqt:secp256r1-mlkem768" ;;
        HybridSecp384r1MLKEM1024Key) echo "hpqt:secp384r1-mlkem1024" ;;
        *) return 1 ;;
    esac
}

# Map KeyType enum name → expected SPKI OID inside the standard PUBLIC KEY PEM
# (per opentdf/platform PR #3563: draft-ietf-lamps-pq-composite-kem-14 +
# draft-connolly-cfrg-xwing-kem-10). The pre-flight check below extracts the
# SPKI AlgorithmIdentifier OID via openssl asn1parse and compares it here.
alg_to_oid() {
    case "$1" in
        HybridXWingKey)              echo "1.3.6.1.4.1.62253.25722" ;;
        HybridSecp256r1MLKEM768Key)  echo "1.3.6.1.5.5.7.6.59" ;;
        HybridSecp384r1MLKEM1024Key) echo "1.3.6.1.5.5.7.6.63" ;;
        *) return 1 ;;
    esac
}

WORK_DIR="$(mktemp -d -t hybrid-pqc-XXXXXX)"
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

##### 2. Pre-flight: confirm KAS publishes hybrid keys
if [[ $SKIP_KAS_CHECK -eq 0 ]] && command -v grpcurl >/dev/null 2>&1; then
    info "Pre-flight: querying KAS for hybrid public keys"
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
            fail "Is the platform running with the PQC-capable KAS branch and the key registered?"
            exit 1
        fi
        # Post-PR-3563: all hybrid PEMs are standard "-----BEGIN PUBLIC KEY-----"
        # (SPKI). Algorithm is identified by the OID inside, not the block name.
        # Verify with openssl asn1parse when available; otherwise just confirm
        # the block type is correct.
        first_line=$(echo "$pem" | head -1)
        if [[ "$first_line" != *"BEGIN PUBLIC KEY"* ]]; then
            fail "$alg: KAS returned a non-SPKI PEM (first line: $first_line)"
            exit 1
        fi
        expected_oid=$(alg_to_oid "$alg_name")
        if command -v openssl >/dev/null 2>&1; then
            actual_oid=$(printf '%s\n' "$pem" | openssl asn1parse 2>/dev/null \
                | awk '/OBJECT/ {sub(/^:/, "", $NF); print $NF; exit}')
            if [[ -z "$actual_oid" ]]; then
                fail "$alg: could not extract SPKI OID via openssl asn1parse"
                exit 1
            fi
            if [[ "$actual_oid" != "$expected_oid" ]]; then
                fail "$alg: SPKI OID mismatch — expected $expected_oid, got $actual_oid"
                exit 1
            fi
            pass "$alg: KAS returns SPKI PEM with OID $actual_oid"
        else
            pass "$alg: KAS returns SPKI PEM (openssl not available; OID not verified)"
        fi
    done
else
    info "Skipping KAS pre-flight check"
fi

##### 3. Round-trip each algorithm
PAYLOAD="$WORK_DIR/payload"
printf 'hybrid pqc round-trip payload @ %s\n' "$(date)" > "$PAYLOAD"
PAYLOAD_BYTES=$(wc -c < "$PAYLOAD" | tr -d ' ')
info "Test payload: $PAYLOAD_BYTES bytes"
echo "       --- plaintext ---"
sed 's/^/       /' < "$PAYLOAD"
echo "       --- end plaintext ---"

failures=()
for alg_name in "${ALGORITHMS[@]}"; do
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
    # In Manifest.java, the Java field `keyType` is annotated with
    # @SerializedName("type"), so the JSON key is "type" (not "keyType").
    keyType=$(jq -r '.encryptionInformation.keyAccess[0].type' <<<"$manifest")
    ephem=$(jq -r '.encryptionInformation.keyAccess[0].ephemeralPublicKey // ""' <<<"$manifest")
    wrapped=$(jq -r '.encryptionInformation.keyAccess[0].wrappedKey // ""' <<<"$manifest")
    if [[ "$keyType" != "hybrid-wrapped" ]]; then
        fail "$alg_name: type='$keyType' (expected 'hybrid-wrapped')"
        echo "    keyAccess[0]:"
        jq '.encryptionInformation.keyAccess[0]' <<<"$manifest" 2>/dev/null | sed 's/^/      /'
        failures+=("$alg_name (bad type: $keyType)")
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
    # ASN.1 SEQUENCE always starts with 0x30 — same invariant HybridCryptoTest checks.
    first_byte=$(base64 -d <<<"$wrapped" 2>/dev/null | xxd -p -l 1 || true)
    if [[ "$first_byte" != "30" ]]; then
        fail "$alg_name: wrappedKey does not start with ASN.1 SEQUENCE (got 0x$first_byte)"
        failures+=("$alg_name (bad envelope)")
        continue
    fi
    pass "$alg_name: manifest OK (hybrid-wrapped, ASN.1 envelope, no ephemeralPublicKey)"
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
        echo "    --- expected (first 200 bytes) ---"
        head -c 200 "$PAYLOAD" | sed 's/^/    /'
        echo
        echo "    --- got (first 200 bytes) ---"
        head -c 200 "$out" | sed 's/^/    /'
        echo
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
    echo "${GREEN}All ${#ALGORITHMS[@]} hybrid algorithm(s) passed round-trip.${RESET}"
    exit 0
else
    echo "${RED}FAILURES (${#failures[@]}):${RESET}"
    printf '  - %s\n' "${failures[@]}"
    exit 1
fi
