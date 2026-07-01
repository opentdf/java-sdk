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
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.net.URL
import java.util.UUID

/**
 * Covers the connect-kotlin request/response path of [AuthInterceptor] — the one that
 * threads the request URL through a ThreadLocal so responseFunction can cache nonces
 * against the correct origin. The okhttp-level retry interceptor is covered separately
 * in DPoPRetryInterceptorTest; this exercises the fragile ThreadLocal handoff directly.
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

            // responseFunction reads the ThreadLocal set by requestFunction and caches
            // the server nonce against the request origin.
            unary.responseFunction.invoke(httpResponse(mapOf("DPoP-Nonce" to listOf("conn-nonce"))))

            val nonce = SignedJWT.parse(ts.getAuthHeaders(kasUrl, "POST").dpopHeader)
                .jwtClaimsSet.getStringClaim("nonce")
            assertThat(nonce).isEqualTo("conn-nonce")
        }
    }

    @Test
    fun requestFunctionThrowClearsThreadLocalSoNoStaleNonceIsCached() {
        val rsaKey = rsaKey()
        MockWebServer().use { tokenServer ->
            // First token fetch fails (so requestFunction throws mid-flight, after it has
            // already stashed the URL in the ThreadLocal); the second succeeds.
            tokenServer.enqueue(MockResponse().setResponseCode(500).setBody("boom"))
            tokenServer.enqueue(
                MockResponse().setBody(fakeTokenResponse).setHeader("Content-Type", "application/json"),
            )
            tokenServer.start()

            val ts = buildTokenSource(tokenServer, rsaKey)
            val unary = AuthInterceptor(ts).unaryFunction()
            val kasUrl = URL("https://kas.example.com/kas")

            assertThatThrownBy { unary.requestFunction.invoke(unaryRequest(kasUrl)) }
                .isInstanceOf(SDKException::class.java)

            // A stray responseFunction with no paired successful requestFunction must not
            // cache against the origin left behind by the throwing call — the catch block
            // in requestFunction is responsible for clearing the ThreadLocal.
            unary.responseFunction.invoke(httpResponse(mapOf("DPoP-Nonce" to listOf("leaked-nonce"))))

            val nonce = SignedJWT.parse(ts.getAuthHeaders(kasUrl, "POST").dpopHeader)
                .jwtClaimsSet.getStringClaim("nonce")
            assertThat(nonce).isNull()
        }
    }
}
