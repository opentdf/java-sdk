# DPoP Nonce Challenge Support — Java SDK

**Date:** 2026-06-16
**Branch:** DSPX-3397-java-sdk

## Problem

When the platform runs with `server.auth.dpop.require_nonce: true`, every DPoP token
request without a nonce claim receives an HTTP 401 with `error=use_dpop_nonce` and a
`DPoP-Nonce` response header. `TokenSource.getToken()` currently throws an
`SDKException` on any non-success token response, so all authenticated operations
fail — including legacy TDF decryption — and the test matrix skips
`dpop_nonce_challenge` tests because `Command.java` and `cli.sh` declare the feature
unsupported.

## Scope

Three files, ~25 lines of change total. No new dependencies. No architectural changes.

## Design

### 1. `TokenSource.getToken()` — proactive lookup + one-shot retry

**Proactive lookup (first attempt):**
Before generating the initial DPoP proof for the token endpoint, look up the nonce
cache by the token endpoint's origin:

```java
String origin = getOrigin(tokenEndpointURI.toURL());
String cachedNonce = nonceCache.get(origin);
SignedJWT proof = (cachedNonce != null)
    ? dpopFactory.createDPoPJWT(method, uri, new Nonce(cachedNonce))
    : dpopFactory.createDPoPJWT(method, uri);
```

This mirrors what `getAuthHeaders()` already does for resource requests, so after the
first nonce handshake all future token refreshes succeed on the first try.

**Retry on `use_dpop_nonce`:**
After `TokenResponse.parse(httpResponse)`, if the response is not a success and the
error code is `use_dpop_nonce`:

1. Extract `DPoP-Nonce` from `httpResponse.getHeaderValue("DPoP-Nonce")`.
2. Call `cacheNonce(tokenEndpointURI.toURL(), nonce)`.
3. Rebuild a fresh `TokenRequest → HTTPRequest`, set the SSL factory, generate a new
   proof using `createDPoPJWT(method, uri, new Nonce(nonce))` (the Nimbus 11.10.1
   `DPoPProofFactory` interface provides this signature), call `send()`.
4. Parse the response. Apply the normal success/failure check — no second retry.

`getOrigin()` and `cacheNonce()` are existing package-private helpers on `TokenSource`;
no new methods needed.

### 2. `Command.java` — declare `dpop_nonce_challenge` supported

File: `cmdline/src/main/java/io/opentdf/platform/Command.java`, line 81.

```java
// before
return "dpop".equalsIgnoreCase(feature) ? 0 : 1;

// after
return ("dpop".equalsIgnoreCase(feature)
     || "dpop_nonce_challenge".equalsIgnoreCase(feature)) ? 0 : 1;
```

### 3. `xtest/sdk/java/cli.sh` — delegate detection to the binary

File: `xtest/sdk/java/cli.sh` (in the **tests repo**), lines 115-116.

```bash
# before
dpop_nonce_challenge)
  echo "dpop_nonce_challenge not supported"
  exit 1
  ;;

# after
dpop_nonce_challenge)
  java -jar "$SCRIPT_DIR"/cmdline.jar supports dpop_nonce_challenge
  exit $?
  ;;
```

## Error handling

- If the retry also fails (wrong nonce, network error, etc.), the existing
  `SDKException` path applies — same message format as today.
- If `DPoP-Nonce` is absent from the 401 body (malformed server response), the
  `use_dpop_nonce` branch falls through to the normal failure path without retrying.

## Testing

**Automated (CI):** Re-run the `xtest.yml` workflow against `DSPX-3397-platform-service`
with `dpop-challenge-enabled: true`. Previously-failing legacy tests (`test_decrypt_*`)
and previously-skipped nonce tests (`test_dpop_server_issued_nonce_retry`) should both
pass.

**Unit test:** Add a test in `TokenSourceTest` (or the existing DPoP test class) that
mocks an HTTP token endpoint returning 401 + `use_dpop_nonce` + `DPoP-Nonce: <value>`
on the first call and 200 on the second, verifying the nonce is included in the retry
proof's JWT claims.

## Files changed

| File | Repo | Change |
|------|------|--------|
| `sdk/src/main/java/io/opentdf/platform/sdk/TokenSource.java` | java-sdk | Nonce lookup + retry in `getToken()` |
| `cmdline/src/main/java/io/opentdf/platform/Command.java` | java-sdk | Declare `dpop_nonce_challenge` supported |
| `xtest/sdk/java/cli.sh` | tests | Delegate detection to binary |
