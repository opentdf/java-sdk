package io.opentdf.platform.sdk

import com.connectrpc.Idempotency
import com.connectrpc.MethodSpec
import com.connectrpc.StreamType
import com.connectrpc.http.HTTPMethod
import com.connectrpc.http.HTTPResponse
import com.connectrpc.http.UnaryHTTPRequest
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic
import com.nimbusds.oauth2.sdk.auth.Secret
import com.nimbusds.oauth2.sdk.id.ClientID
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okio.Buffer
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.net.URL
import java.util.UUID

/**
 * Covers the connect-kotlin request/response path of [AuthInterceptor] — the one that threads the
 * request URL from requestFunction to responseFunction (via a per-call closure-local) so nonces are
 * cached against the correct origin. connect-kotlin builds a fresh interceptor + function pair per
 * call, so each pair's URL is isolated. The okhttp-level retry interceptor is covered separately in
 * DPoPRetryInterceptorTest.
 */
class AuthInterceptorConnectPathTest {

    private val fakeTokenResponse =
        "{\"access_token\":\"test-token\",\"token_type\":\"DPoP\",\"expires_in\":3600}"

    private fun rsaKey(): RSAKey = RSAKeyGenerator(2048)
        .keyUse(KeyUse.SIGNATURE)
        .keyID(UUID.randomUUID().toString())
        .generate()

    private fun buildTokenSource(tokenServer: MockWebServer, rsaKey: RSAKey) = TokenSource(
        ClientSecretBasic(ClientID("test-client"), Secret("test-secret")),
        rsaKey,
        JWSAlgorithm.RS256,
        tokenServer.url("/token").toUri(),
        ClientCredentialsGrant(),
        null,
    )

    private fun unaryRequest(url: URL) = UnaryHTTPRequest(
        url = url,
        contentType = "application/grpc",
        timeout = null,
        headers = emptyMap(),
        methodSpec = MethodSpec("test.Service/Method", Any::class, Any::class, StreamType.UNARY, Idempotency.UNKNOWN),
        message = Buffer(),
        httpMethod = HTTPMethod.POST,
    )

    private fun httpResponse(headers: Map<String, List<String>>) = HTTPResponse(
        status = 200,
        headers = headers,
        message = Buffer(),
        trailers = emptyMap(),
        cause = null,
    )

    @Test
    fun requestFunctionAddsDPoPHeadersAndResponseFunctionCachesNonceForOrigin() {
        val rsaKey = rsaKey()
        MockWebServer().use { tokenServer ->
            repeat(2) {
                tokenServer.enqueue(
                    MockResponse().setBody(fakeTokenResponse).setHeader("Content-Type", "application/json"),
                )
            }
            tokenServer.start()

            val ts = buildTokenSource(tokenServer, rsaKey)
            val unary = AuthInterceptor(ts).unaryFunction()
            val kasUrl = URL("https://kas.example.com/kas")

            val outgoing = unary.requestFunction.invoke(unaryRequest(kasUrl))
            assertThat(outgoing.headers["Authorization"]!!.first()).startsWith("DPoP ")
            assertThat(outgoing.headers["DPoP"]!!.first()).isNotEmpty()

            // responseFunction reads the URL stashed by requestFunction and caches the server
            // nonce against the request origin.
            unary.responseFunction.invoke(httpResponse(mapOf("DPoP-Nonce" to listOf("conn-nonce"))))

            val nonce = SignedJWT.parse(ts.getAuthHeaders(kasUrl, "POST").dpopHeader)
                .jwtClaimsSet.getStringClaim("nonce")
            assertThat(nonce).isEqualTo("conn-nonce")
        }
    }

    @Test
    fun eachUnaryFunctionPairIsolatesItsUrlSoNoncesCacheAgainstTheirOwnOrigin() {
        // connect-kotlin builds a fresh interceptor + function pair per call. Each unaryFunction()
        // invocation therefore holds its own request URL in a closure-local, so interleaved calls
        // to two different origins never cross-contaminate their cached nonces (the failure mode the
        // previous ThreadLocal handoff had to guard against by hand).
        val rsaKey = rsaKey()
        MockWebServer().use { tokenServer ->
            repeat(2) {
                tokenServer.enqueue(
                    MockResponse().setBody(fakeTokenResponse).setHeader("Content-Type", "application/json"),
                )
            }
            tokenServer.start()

            val ts = buildTokenSource(tokenServer, rsaKey)
            val interceptor = AuthInterceptor(ts)
            val urlA = URL("https://kas-a.example.com/kas")
            val urlB = URL("https://kas-b.example.com/kas")

            // Two independent call pairs, requests issued before either response settles.
            val pairA = interceptor.unaryFunction()
            val pairB = interceptor.unaryFunction()
            pairA.requestFunction.invoke(unaryRequest(urlA))
            pairB.requestFunction.invoke(unaryRequest(urlB))

            // Responses settle out of order; each must cache against its own pair's origin.
            pairB.responseFunction.invoke(httpResponse(mapOf("DPoP-Nonce" to listOf("nonce-B"))))
            pairA.responseFunction.invoke(httpResponse(mapOf("DPoP-Nonce" to listOf("nonce-A"))))

            val nonceA = SignedJWT.parse(ts.getAuthHeaders(urlA, "POST").dpopHeader)
                .jwtClaimsSet.getStringClaim("nonce")
            val nonceB = SignedJWT.parse(ts.getAuthHeaders(urlB, "POST").dpopHeader)
                .jwtClaimsSet.getStringClaim("nonce")
            assertThat(nonceA).isEqualTo("nonce-A")
            assertThat(nonceB).isEqualTo("nonce-B")
        }
    }
}
