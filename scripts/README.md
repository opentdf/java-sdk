# scripts/

Developer scripts for the OpenTDF Java SDK. Not bundled with the published
artifacts.

## `test-mlkem.sh`

End-to-end test of the Java SDK's pure ML-KEM (FIPS 203) post-quantum key
wrapping (`mlkem:768`, `mlkem:1024`) against a locally running OpenTDF
platform. Per algorithm it:

1. Confirms the KAS publishes an ML-KEM PEM for that algorithm (`grpcurl`
   pre-flight, optional).
2. Encrypts a small payload via the `cmdline` jar using
   `--encap-key-type=MLKEM768Key` (or `MLKEM1024Key`).
3. Asserts the resulting TDF manifest has:
   - `keyAccess[0].type == "wrapped"` (reuses the existing RSA-wrapped slot;
     KAS disambiguates by registered key algorithm)
   - `keyAccess[0].ephemeralPublicKey` empty
   - `keyAccess[0].wrappedKey` decoded length equals
     `ciphertextSize + 12 (nonce) + 32 (DEK) + 16 (GCM tag)`
4. Decrypts the TDF — exercises the KAS rewrap path with server-side ML-KEM
   decapsulation.
5. Diffs the decrypted payload against the original.

On success the script prints the plaintext, the full `keyAccess[0]` (KAO),
and the decrypted output for each algorithm.

### Prerequisites

| Requirement | Notes |
|---|---|
| **JDK 17** | The project's Kotlin compiler can't parse newer JDK version strings. Use Corretto/Temurin/etc. 17. On macOS: `export JAVA_HOME=$(/usr/libexec/java_home -v 17)`. |
| **Maven 3.9+** | Project uses standard `mvn clean install`. |
| **Buf token** | Proto generation requires auth. Either `buf registry login` once, or export `BUF_INPUT_HTTPS_USERNAME` / `BUF_INPUT_HTTPS_PASSWORD`. |
| **`non-fips` Maven profile (default)** | Pure ML-KEM needs `bcprov-jdk18on` at compile/runtime scope (no JDK 11 stdlib equivalent; the JCA KEM API is JDK 21+). The default `non-fips` profile pulls it in. The `fips` profile does not yet support ML-KEM — follow-up. |
| **Local platform with ML-KEM support** | `opentdf/platform` checked out on a branch with PR 3491 applied; `preview.mlkem_enabled: true` in `opentdf-dev.yaml`; an `mlkem:768` KAS key registered. ML-KEM-1024 has no Go reference at the time of writing — Java unit tests cover it but end-to-end is 768-only for now. |
| **CLI tools** | `java`, `mvn`, `unzip`, `jq` on `PATH`. `grpcurl` optional but recommended (drives the pre-flight check). |

### Run it

From the repo root:

```bash
# Default — mlkem:768 only (Go KAS scope)
PLATFORM_ENDPOINT=http://localhost:8080 scripts/test-mlkem.sh

# Skip rebuild on iterative runs
scripts/test-mlkem.sh --skip-build

# Include 1024 (only works once Go KAS supports it)
scripts/test-mlkem.sh --algorithms MLKEM768Key,MLKEM1024Key

# Skip the grpcurl pre-flight (use when grpcurl isn't installed)
scripts/test-mlkem.sh --skip-kas-check
```

### Configuration

| Flag / Env | Default | Description |
|---|---|---|
| `--platform-endpoint` / `PLATFORM_ENDPOINT` | `http://localhost:8080` | Platform base URL |
| `--kas-url` / `KAS_URL` | same as platform endpoint | KAS URL passed to cmdline `encrypt` |
| `--client-id` / `CLIENT_ID` | `opentdf-sdk` | OIDC client id |
| `--client-secret` / `CLIENT_SECRET` | `secret` | OIDC client secret |
| `--attr` / `DATA_ATTR` | `https://example.com/attr/attr1/value/value1` | Attribute FQN attached to encrypt |
| `--algorithms` | `MLKEM768Key` | Comma-separated subset of `KeyType` enum names |
| `--skip-build` | (off) | Reuse `cmdline/target/cmdline.jar` |
| `--skip-kas-check` | (off) | Skip the `grpcurl` pre-flight |

### Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `Maven build failed ... Buf API token` | Run `buf registry login`, or export `BUF_INPUT_HTTPS_USERNAME` and `BUF_INPUT_HTTPS_PASSWORD`. |
| `Maven build failed ... Kotlin ... isAtLeastJava9` (stack trace) | JDK too new. `export JAVA_HOME=$(/usr/libexec/java_home -v 17)` and rerun. |
| `KAS returned no publicKey` | Platform isn't running, isn't reachable at `$PLATFORM_ENDPOINT`, or `preview.mlkem_enabled` is off. |
| `KAS returned a non-ML-KEM PEM` | Platform is up but no ML-KEM KAS key is registered for that algorithm. Register one (e.g. via `otdfctl`) and rerun. |
| `type='null'` (manifest assertion) | You're on an old branch where `TDF.java` doesn't yet route ML-KEM algorithms. Pull the latest branch HEAD. |
| `decrypt failed` after manifest passes | KAS-side rewrap doesn't yet support ML-KEM, or the Go SDK's HKDF discrepancy (see Known SDK gap below) hasn't been resolved. |
| `wrappedKey decoded length N != expected M` | Wire format drift — likely your local Java SDK has a different layout than what was tested. |

### Known SDK gap

`KeyType.fromAlgorithm` and `KeyType.fromPublicKeyAlgorithm`
(`sdk/src/main/java/io/opentdf/platform/sdk/KeyType.java`) don't yet map the
ML-KEM algorithm protobuf enums. Auto-discovery via the KAS registry
(`Config.KASInfo.fromKeyAccessServer`) will throw `IllegalArgumentException`
once the platform's proto definitions include `KAS_PUBLIC_KEY_ALG_ENUM_MLKEM_*`
values. This script bypasses that path by using `--encap-key-type` explicitly;
extending the script to also exercise registry-discovery should wait until
the mapping is added.

### Reference

- Go server: opentdf/platform PR 3491 (`lib/ocrypto/mlkem_key_pair.go`)
- Go SDK: opentdf/platform PR 3486 (`wrapKeyWithMLKEM`)
- Jira: DSPX-2399
