# scripts/

Developer scripts for the OpenTDF Java SDK. Not bundled with the published
artifacts.

## `test-hybrid-pqc.sh`

End-to-end test of the Java SDK's hybrid post-quantum key wrapping
(`hpqt:xwing`, `hpqt:secp256r1-mlkem768`, `hpqt:secp384r1-mlkem1024`) against
a locally running OpenTDF platform. Per algorithm it:

1. Confirms the KAS publishes a hybrid PEM for that algorithm (`grpcurl`
   pre-flight, optional).
2. Encrypts a small payload via the `cmdline` jar using
   `--encap-key-type=<Hybrid…Key>`.
3. Asserts the resulting TDF manifest has:
   - `keyAccess[0].type == "hybrid-wrapped"`
   - `keyAccess[0].ephemeralPublicKey` empty (the ephemeral material is
     carried inside the ASN.1 envelope in `wrappedKey`)
   - `keyAccess[0].wrappedKey` starts with the ASN.1 SEQUENCE byte `0x30`
4. Decrypts the TDF (this is the step that actually exercises hybrid
   decapsulation on the KAS rewrap path).
5. Diffs the decrypted payload against the original.

On success the script also prints the plaintext, the full `keyAccess[0]`
(KAO), and the decrypted output for each algorithm so you can eyeball the
artifacts.

### Prerequisites

| Requirement | Notes |
|---|---|
| **JDK 17** | The project's Kotlin compiler can't parse newer JDK version strings. Use Corretto/Temurin/etc. 17. On macOS: `export JAVA_HOME=$(/usr/libexec/java_home -v 17)`. |
| **Maven 3.9+** | Project uses standard `mvn clean install`. |
| **Buf token** | Proto generation requires auth. Either `buf registry login` once, or export `BUF_INPUT_HTTPS_USERNAME` / `BUF_INPUT_HTTPS_PASSWORD`. |
| **`sdk-pqc-bc` module on the classpath** | The BC-backed hybrid PQC implementation lives in the optional `sdk-pqc-bc` sibling module. `cmdline` declares it at runtime scope, so the test script picks it up automatically through `ServiceLoader`. FIPS deployments should omit `sdk-pqc-bc` and accept that hybrid PQC is unavailable in that mode — `TDF.createKeyAccess` throws a clean `SDKException` directing the user to add it. |
| **Local platform with PQC support** | `opentdf/platform` checked out on a branch that implements `hpqt:*` KAS keys + the `hybrid-wrapped` rewrap path. See the platform repo for bring-up (`docker compose` / `make start`). |
| **Hybrid KAS keys registered** | The local platform must have a KAS key registered for each `hpqt:*` algorithm you intend to test. Use `otdfctl` (or platform tooling) to register them. |
| **CLI tools** | `java`, `mvn`, `unzip`, `jq` on `PATH`. `grpcurl` optional but recommended (drives the pre-flight check). |

### Run it

From the repo root:

```bash
# Full run — builds cmdline, pre-flight check, all 3 algorithms
PLATFORM_ENDPOINT=http://localhost:8080 scripts/test-hybrid-pqc.sh

# Reuse an already-built cmdline jar (much faster on iterative runs)
scripts/test-hybrid-pqc.sh --skip-build

# One algorithm only
scripts/test-hybrid-pqc.sh --algorithms HybridXWingKey

# Multiple specific algorithms (comma-separated)
scripts/test-hybrid-pqc.sh --algorithms HybridXWingKey,HybridSecp256r1MLKEM768Key

# Skip the grpcurl pre-flight (use when grpcurl isn't installed)
scripts/test-hybrid-pqc.sh --skip-kas-check
```

### Configuration

All defaults match the existing CI workflow (`.github/workflows/checks.yaml`).
Override via flag or env var:

| Flag / Env | Default | Description |
|---|---|---|
| `--platform-endpoint` / `PLATFORM_ENDPOINT` | `http://localhost:8080` | Platform base URL |
| `--kas-url` / `KAS_URL` | same as platform endpoint | KAS URL passed to cmdline `encrypt` |
| `--client-id` / `CLIENT_ID` | `opentdf-sdk` | OIDC client id |
| `--client-secret` / `CLIENT_SECRET` | `secret` | OIDC client secret |
| `--attr` / `DATA_ATTR` | `https://example.com/attr/attr1/value/value1` | Attribute FQN attached to encrypt |
| `--algorithms` | all three | Comma-separated subset of `KeyType` enum names |
| `--skip-build` | (off) | Reuse `cmdline/target/cmdline.jar` |
| `--skip-kas-check` | (off) | Skip the `grpcurl` pre-flight |

### Expected output

```text
[OK]   hpqt:xwing: KAS returns SPKI PEM with OID 1.3.6.1.4.1.62253.25722
[OK]   hpqt:secp256r1-mlkem768: KAS returns SPKI PEM with OID 1.3.6.1.5.5.7.6.59
[OK]   hpqt:secp384r1-mlkem1024: KAS returns SPKI PEM with OID 1.3.6.1.5.5.7.6.63
...
[OK]   HybridXWingKey: manifest OK (hybrid-wrapped, ASN.1 envelope, no ephemeralPublicKey)
[OK]   HybridXWingKey: round-trip OK
...
All 3 hybrid algorithm(s) passed round-trip.
```

Exit code is 0 on success, 1 on any algorithm failure (other algorithms still
attempted), 2 on misuse.

### Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `Maven build failed ... Buf API token` | Run `buf registry login`, or export `BUF_INPUT_HTTPS_USERNAME` and `BUF_INPUT_HTTPS_PASSWORD`. |
| `Maven build failed ... Kotlin ... isAtLeastJava9` (stack trace) | JDK too new. `export JAVA_HOME=$(/usr/libexec/java_home -v 17)` and rerun. |
| `KAS returned no publicKey` | Platform isn't running, or isn't reachable at `$PLATFORM_ENDPOINT`. |
| `KAS returned a non-hybrid PEM` | The platform is up but no hybrid KAS key is registered for that algorithm. Register one and rerun. |
| `keyType='null'` (manifest assertion) | You're on an old branch where `TDF.java` doesn't yet route hybrid algorithms. Pull the latest branch HEAD. |
| `decrypt failed` after manifest passes | KAS-side rewrap doesn't yet support the `hybrid-wrapped` keyType. Check the platform branch has the matching server change. |

## `test-mlkem.sh`

End-to-end test of the Java SDK's pure ML-KEM (FIPS 203) key wrapping
(`mlkem:768`, `mlkem:1024`) against a locally running OpenTDF platform.
Same shape as `test-hybrid-pqc.sh` (encrypt → assert manifest → KAS rewrap
→ decrypt → diff) with three pure-ML-KEM specifics:

- `keyAccess[0].type` is `"wrapped"` (not `"hybrid-wrapped"`) — pure ML-KEM
  reuses the RSA slot; the KAS disambiguates from RSA by the registered key
  algorithm.
- `wrappedKey` is a raw concat `mlkemCiphertext || AES-GCM(IV(12) || DEK(32)
  || tag(16))` rather than an ASN.1 SEQUENCE. The script asserts the exact
  byte length: `ciphertextSize + 60` (1088+60 = 1148 for ML-KEM-768;
  1568+60 = 1628 for ML-KEM-1024).
- Pre-flight OIDs are the NIST FIPS 203 OIDs:
  `2.16.840.1.101.3.4.4.2` for ML-KEM-768 and
  `2.16.840.1.101.3.4.4.3` for ML-KEM-1024.

### Run it

```bash
# Full run — builds cmdline, pre-flight check, both variants
PLATFORM_ENDPOINT=http://localhost:8080 scripts/test-mlkem.sh

# One variant only
scripts/test-mlkem.sh --algorithms MLKEM768Key

# Reuse an already-built cmdline jar (much faster on iterative runs)
scripts/test-mlkem.sh --skip-build
```

All other flags (`--platform-endpoint`, `--kas-url`, `--client-id`,
`--client-secret`, `--attr`, `--skip-kas-check`) match
`test-hybrid-pqc.sh` — see the configuration table above.

### Prerequisites

Same as `test-hybrid-pqc.sh`. The KAS-side requirement is that
`mlkem:768` (and optionally `mlkem:1024`) public keys are registered.

### Known SDK gap (pure ML-KEM)

`KeyType.fromAlgorithm` / `fromPublicKeyAlgorithm` don't yet map the pure
ML-KEM protobuf enums. The platform proto stubs we currently build against
(`protocol/go/v0.34.0`) only have the hybrid `ALGORITHM_HPQT_*` set — no
`ALGORITHM_MLKEM_768` / `_1024`. Until the platform release we depend on
adds those values, registry-discovery via
`Config.KASInfo.fromKeyAccessServer` will throw `IllegalArgumentException`
for ML-KEM. This script sidesteps it by passing `--encap-key-type=MLKEM*Key`
explicitly. When the proto bump lands, add two cases to each switch in
`KeyType.java` and the script can also be extended to exercise the
registry-discovery path.
