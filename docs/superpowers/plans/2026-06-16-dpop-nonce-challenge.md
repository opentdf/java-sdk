# DPoP Nonce Challenge Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Java SDK correctly handle DPoP nonce challenges from the authorization server (token endpoint) and declare `dpop_nonce_challenge` support, so that legacy TDF decryption and explicit DPoP nonce tests pass when the platform runs with `require_nonce: true`.

**Architecture:** Add proactive nonce cache lookup and a one-shot retry to `TokenSource.getToken()` — when the token endpoint returns `error=use_dpop_nonce`, extract the `DPoP-Nonce` response header, cache it per-origin, rebuild the token request with the nonce in the DPoP proof, and retry once. Then declare support in `Command.java` and the xtest CLI shim.

**Tech Stack:** Java 11, Nimbus oauth2-oidc-sdk 11.10.1, OkHttp MockWebServer (tests), JUnit 5, AssertJ, Picocli

---

## File Map

| File | Repo | Change |
|------|------|--------|
| `sdk/src/main/java/io/opentdf/platform/sdk/TokenSource.java` | java-sdk | Nonce lookup + retry in `getToken()` |
| `sdk/src/test/java/io/opentdf/platform/sdk/TokenSourceTest.java` | java-sdk | Two new tests: retry and proactive |
| `cmdline/src/main/java/io/opentdf/platform/Command.java` | java-sdk | Declare `dpop_nonce_challenge` supported |
| `cmdline/src/test/java/io/opentdf/platform/CommandTest.java` | java-sdk | New: test supports command exit codes |
| `xtest/sdk/java/cli.sh` | tests | Delegate `dpop_nonce_challenge` detection to binary |

---

## Task 1: Token endpoint nonce retry in TokenSource

**Files:**
- Modify: `sdk/src/main/java/io/opentdf/platform/sdk/TokenSource.java` (`getToken()` method, lines 162–216)
- Modify: `sdk/src/test/java/io/opentdf/platform/sdk/TokenSourceTest.java`

### - [ ] Step 1: Write two failing tests

Add these two tests to `TokenSourceTest.java`, after the `emptyNonceIsNotCached` test. The existing `buildTokenSource` helper and imports cover everything needed; add `RecordedRequest` to the imports.

```java
// Add to imports:
import okhttp3.mockwebserver.RecordedRequest;
```

```java
@Test
void getToken_retriesWithNonceOnUseDpopNonce() throws Exception {
    RSAKey rsaKey = new RSAKeyGenerator(2048)
            .keyUse(KeyUse.SIGNATURE)
            .keyID(UUID.randomUUID().toString())
            .generate();
    try (MockWebServer tokenServer = new MockWebServer()) {
        // First: 401 use_dpop_nonce
        tokenServer.enqueue(new MockResponse()
                .setResponseCode(401)
                .setHeader("Content-Type", "application/json")
                .addHeader("DPoP-Nonce", "retry-nonce-abc")
                .setBody("{\"error\":\"use_dpop_nonce\",\"error_description\":\"nonce required\"}"));
        // Second: success
        tokenServer.enqueue(new MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody("{\"access_token\":\"real-token\",\"token_type\":\"DPoP\",\"expires_in\":3600}"));
        tokenServer.start();

        TokenSource ts = buildTokenSource(tokenServer, rsaKey);
        URL resourceUrl = new URL("https://kas.example.com/kas");

        TokenSource.AuthHeaders headers = ts.getAuthHeaders(resourceUrl, "POST");

        assertThat(headers.getAuthHeader()).isEqualTo("DPoP real-token");
        assertThat(tokenServer.getRequestCount()).isEqualTo(2);

        RecordedRequest first = tokenServer.takeRequest();
        String firstNonce = SignedJWT.parse(first.getHeader("DPoP"))
                .getJWTClaimsSet().getStringClaim("nonce");
        assertThat(firstNonce).isNull();

        RecordedRequest second = tokenServer.takeRequest();
        String secondNonce = SignedJWT.parse(second.getHeader("DPoP"))
                .getJWTClaimsSet().getStringClaim("nonce");
        assertThat(secondNonce).isEqualTo("retry-nonce-abc");
    }
}

@Test
void getToken_usesProactivelyCachedNonce() throws Exception {
    RSAKey rsaKey = new RSAKeyGenerator(2048)
            .keyUse(KeyUse.SIGNATURE)
            .keyID(UUID.randomUUID().toString())
            .generate();
    try (MockWebServer tokenServer = new MockWebServer()) {
        tokenServer.enqueue(new MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody("{\"access_token\":\"proactive-token\",\"token_type\":\"DPoP\",\"expires_in\":3600}"));
        tokenServer.start();

        TokenSource ts = buildTokenSource(tokenServer, rsaKey);
        // Pre-seed the cache for the token endpoint origin
        ts.cacheNonce(tokenServer.url("/token").url(), "proactive-nonce");

        ts.getAuthHeaders(new URL("https://kas.example.com/kas"), "POST");

        assertThat(tokenServer.getRequestCount()).isEqualTo(1);

        RecordedRequest request = tokenServer.takeRequest();
        String nonceClaim = SignedJWT.parse(request.getHeader("DPoP"))
                .getJWTClaimsSet().getStringClaim("nonce");
        assertThat(nonceClaim).isEqualTo("proactive-nonce");
    }
}
```

### - [ ] Step 2: Run tests to confirm they fail

```bash
cd /Users/dmihalcik/Documents/GitHub/worktrees/DSPX-3397-java-sdk/sdk
mvn test -Dtest=TokenSourceTest#getToken_retriesWithNonceOnUseDpopNonce+getToken_usesProactivelyCachedNonce -q
```

Expected: both tests FAIL. `getToken_retriesWithNonceOnUseDpopNonce` fails because `getToken()` throws `SDKException("failure to get token ... error code = [use_dpop_nonce]")` on the first 401. `getToken_usesProactivelyCachedNonce` fails because the token endpoint 401 is not expected (only one response is queued).

### - [ ] Step 3: Implement the fix in TokenSource.getToken()

Replace the body of the `if (token == null || isTokenExpired())` block in `TokenSource.java` (approximately lines 168–206). Keep the surrounding `try/catch` and `synchronized` untouched.

The `Nonce` import is already present at line 18. No new imports needed.

```java
if (token == null || isTokenExpired()) {
    logger.trace("The current access token is expired or empty, getting a new one");

    DPoPProofFactory dpopFactory = new DefaultDPoPProofFactory(dpopJwk, dpopAlg);

    // Proactively use any cached nonce for the token endpoint (RFC 9449 §8)
    String cachedNonce = nonceCache.get(getOrigin(tokenEndpointURI.toURL()));

    TokenRequest tokenRequest = new TokenRequest(this.tokenEndpointURI, clientAuth, authzGrant, null);
    HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
    if (sslSocketFactory != null) {
        httpRequest.setSSLSocketFactory(sslSocketFactory);
    }
    SignedJWT proof = (cachedNonce != null)
            ? dpopFactory.createDPoPJWT(httpRequest.getMethod().name(), httpRequest.getURI(), new Nonce(cachedNonce))
            : dpopFactory.createDPoPJWT(httpRequest.getMethod().name(), httpRequest.getURI());
    httpRequest.setDPoP(proof);

    HTTPResponse httpResponse = httpRequest.send();
    TokenResponse tokenResponse = TokenResponse.parse(httpResponse);

    // RFC 9449 §8: if AS requires a nonce, cache it and retry once
    if (!tokenResponse.indicatesSuccess()) {
        ErrorObject error = tokenResponse.toErrorResponse().getErrorObject();
        if ("use_dpop_nonce".equals(error.getCode().getValue())) {
            String dpopNonce = httpResponse.getHeaderValue("DPoP-Nonce");
            if (dpopNonce != null) {
                cacheNonce(tokenEndpointURI.toURL(), dpopNonce);
                TokenRequest retryRequest = new TokenRequest(tokenEndpointURI, clientAuth, authzGrant, null);
                HTTPRequest retryHttpRequest = retryRequest.toHTTPRequest();
                if (sslSocketFactory != null) {
                    retryHttpRequest.setSSLSocketFactory(sslSocketFactory);
                }
                SignedJWT retryProof = dpopFactory.createDPoPJWT(
                        retryHttpRequest.getMethod().name(),
                        retryHttpRequest.getURI(),
                        new Nonce(dpopNonce));
                retryHttpRequest.setDPoP(retryProof);
                httpResponse = retryHttpRequest.send();
                tokenResponse = TokenResponse.parse(httpResponse);
            }
        }
        if (!tokenResponse.indicatesSuccess()) {
            ErrorObject finalError = tokenResponse.toErrorResponse().getErrorObject();
            throw new SDKException("failure to get token. description = [" + finalError.getDescription()
                    + "] error code = [" + finalError.getCode()
                    + "] error uri = [" + finalError.getURI() + "]");
        }
    }

    var tokens = tokenResponse.toSuccessResponse().getTokens();
    if (tokens.getDPoPAccessToken() != null) {
        logger.trace("retrieved a new DPoP access token");
    } else if (tokens.getAccessToken() != null) {
        logger.trace("retrieved a new access token");
    } else {
        logger.trace("got an access token of unknown type");
    }

    this.token = tokens.getAccessToken();

    if (token.getLifetime() != 0) {
        this.tokenExpiryTime = Instant.now().plusSeconds(token.getLifetime() / 3);
    }
}
```

### - [ ] Step 4: Run the full TokenSourceTest suite

```bash
cd /Users/dmihalcik/Documents/GitHub/worktrees/DSPX-3397-java-sdk/sdk
mvn test -Dtest=TokenSourceTest -q
```

Expected: all tests PASS (the 6 existing + 2 new).

### - [ ] Step 5: Commit

```bash
cd /Users/dmihalcik/Documents/GitHub/worktrees/DSPX-3397-java-sdk
git add sdk/src/main/java/io/opentdf/platform/sdk/TokenSource.java \
        sdk/src/test/java/io/opentdf/platform/sdk/TokenSourceTest.java
git commit -m "feat(sdk): retry token request with nonce on use_dpop_nonce (RFC 9449 §8)"
```

---

## Task 2: Declare dpop_nonce_challenge in Command.java

**Files:**
- Modify: `cmdline/src/main/java/io/opentdf/platform/Command.java` (line 81)
- Create: `cmdline/src/test/java/io/opentdf/platform/CommandTest.java`

### - [ ] Step 6: Create the test file

Create `cmdline/src/test/java/io/opentdf/platform/CommandTest.java`:

```java
package io.opentdf.platform;

import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import static org.assertj.core.api.Assertions.assertThat;

class CommandTest {

    @Test
    void supports_dpop_exits_0() {
        int code = new CommandLine(new Command()).execute("supports", "dpop");
        assertThat(code).isEqualTo(0);
    }

    @Test
    void supports_dpop_nonce_challenge_exits_0() {
        int code = new CommandLine(new Command()).execute("supports", "dpop_nonce_challenge");
        assertThat(code).isEqualTo(0);
    }

    @Test
    void supports_unknown_feature_exits_1() {
        int code = new CommandLine(new Command()).execute("supports", "unknown_feature");
        assertThat(code).isEqualTo(1);
    }
}
```

### - [ ] Step 7: Run test to confirm it fails

```bash
cd /Users/dmihalcik/Documents/GitHub/worktrees/DSPX-3397-java-sdk/cmdline
mvn test -Dtest=CommandTest#supports_dpop_nonce_challenge_exits_0 -q
```

Expected: FAIL — exit code is 1, not 0.

### - [ ] Step 8: Update Command.java line 81

Change the single line inside `Supports.call()`:

```java
// Before:
return "dpop".equalsIgnoreCase(feature) ? 0 : 1;

// After:
return ("dpop".equalsIgnoreCase(feature) || "dpop_nonce_challenge".equalsIgnoreCase(feature)) ? 0 : 1;
```

### - [ ] Step 9: Run CommandTest suite

```bash
cd /Users/dmihalcik/Documents/GitHub/worktrees/DSPX-3397-java-sdk/cmdline
mvn test -Dtest=CommandTest -q
```

Expected: all 3 tests PASS.

### - [ ] Step 10: Commit

```bash
cd /Users/dmihalcik/Documents/GitHub/worktrees/DSPX-3397-java-sdk
git add cmdline/src/main/java/io/opentdf/platform/Command.java \
        cmdline/src/test/java/io/opentdf/platform/CommandTest.java
git commit -m "feat(cmdline): declare dpop_nonce_challenge support"
```

---

## Task 3: Update xtest cli.sh feature detection

**Files:**
- Modify: `xtest/sdk/java/cli.sh` in the **tests repo** (`/Users/dmihalcik/Documents/GitHub/opentdf/tests`)

### - [ ] Step 11: Update cli.sh

In `xtest/sdk/java/cli.sh`, find the `dpop_nonce_challenge)` case (around line 115) and replace the hardcoded failure with a delegation to the binary:

```bash
# Before:
dpop_nonce_challenge)
  echo "dpop_nonce_challenge not supported"
  exit 1
  ;;

# After:
dpop_nonce_challenge)
  java -jar "$SCRIPT_DIR"/cmdline.jar supports dpop_nonce_challenge
  exit $?
  ;;
```

### - [ ] Step 12: Smoke-test the detection locally

After building the cmdline jar (`mvn package -pl cmdline -DskipTests -q` in the java-sdk worktree) and placing it where the test harness expects it:

```bash
cd /Users/dmihalcik/Documents/GitHub/opentdf/tests/xtest/sdk/java
bash cli.sh dpop_nonce_challenge
echo "Exit code: $?"
```

Expected output: exit code `0`.

### - [ ] Step 13: Commit in the tests repo

```bash
cd /Users/dmihalcik/Documents/GitHub/opentdf/tests
git add xtest/sdk/java/cli.sh
git commit -m "feat(java-sdk): delegate dpop_nonce_challenge detection to binary"
```

---

## Task 4: Full test run

### - [ ] Step 14: Run the full sdk module test suite

```bash
cd /Users/dmihalcik/Documents/GitHub/worktrees/DSPX-3397-java-sdk/sdk
mvn test -q
```

Expected: all tests PASS, no regressions.

### - [ ] Step 15: Build the cmdline jar

```bash
cd /Users/dmihalcik/Documents/GitHub/worktrees/DSPX-3397-java-sdk
mvn package -DskipTests -q
```

Expected: `cmdline/target/cmdline-*.jar` produced with no errors.

### - [ ] Step 16: Push java-sdk branch and trigger CI

```bash
cd /Users/dmihalcik/Documents/GitHub/worktrees/DSPX-3397-java-sdk
git push origin DSPX-3397-java-sdk
```

Then re-trigger `xtest.yml` in the tests repo against the updated branches:

```bash
gh workflow run xtest.yml \
  --repo opentdf/tests \
  --ref fix-dpop-nonce-challenge \
  --field platform-ref=DSPX-3397-platform-service \
  --field js-ref=DSPX-3397-web-sdk \
  --field java-ref=DSPX-3397-java-sdk
```

Expected: Java legacy tests (`test_decrypt_*`) pass; `test_dpop_server_issued_nonce_retry` and related nonce tests run and pass (no longer skipped).
