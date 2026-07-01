package io.opentdf.platform.sdk

import com.connectrpc.Interceptor
import com.connectrpc.StreamFunction
import com.connectrpc.UnaryFunction
import com.connectrpc.http.UnaryHTTPRequest
import com.connectrpc.http.clone
import com.nimbusds.jwt.SignedJWT
import org.slf4j.LoggerFactory
import java.net.URL

internal class AuthInterceptor(private val ts: TokenSource) : Interceptor {
    private val logger = LoggerFactory.getLogger(AuthInterceptor::class.java)
    // The connect-kotlin Interceptor API exposes no per-call context to thread the
    // request URL into responseFunction. ThreadLocal is the workaround, relying on
    // connect-kotlin's contract that requestFunction and responseFunction for a single
    // unary call run synchronously on the same thread. If that assumption ever breaks,
    // nonces could be cached against the wrong origin. The okhttp-level
    // dpopRetryInterceptor below avoids the issue by reading the URL straight from
    // chain.request().
    private val requestUrl = ThreadLocal<URL>()

    override fun streamFunction(): StreamFunction {
        return StreamFunction(
            requestFunction = { request ->
                val requestHeaders = mutableMapOf<String, List<String>>()
                val authHeaders = ts.getAuthHeaders(request.url, "POST")
                requestHeaders["Authorization"] = listOf(authHeaders.authHeader)
                authHeaders.dpopHeader?.let { requestHeaders["DPoP"] = listOf(it) }

                logger.debug("DPoP path=stream url={} method=POST authScheme={} {}",
                        request.url, authScheme(authHeaders.authHeader), dpopSummary(authHeaders.dpopHeader))

                return@StreamFunction request.clone(
                    url = request.url,
                    contentType = request.contentType,
                    headers = requestHeaders,
                    timeout = request.timeout,
                    methodSpec = request.methodSpec,
                )
            },
            requestBodyFunction = { resp -> resp },
            streamResultFunction = { streamResult -> streamResult },
        )
    }

    override fun unaryFunction(): UnaryFunction {
        return UnaryFunction(
            requestFunction = { request ->
                // Clear any value left behind by an earlier requestFunction that
                // threw before its paired responseFunction could run.
                requestUrl.remove()
                requestUrl.set(request.url)
                try {
                    val requestHeaders = mutableMapOf<String, List<String>>()
                    val authHeaders = ts.getAuthHeaders(request.url, request.httpMethod.name)
                    requestHeaders["Authorization"] = listOf(authHeaders.authHeader)
                    authHeaders.dpopHeader?.let { requestHeaders["DPoP"] = listOf(it) }

                    logger.debug("DPoP path=unary url={} method={} authScheme={} {}",
                            request.url, request.httpMethod.name,
                            authScheme(authHeaders.authHeader), dpopSummary(authHeaders.dpopHeader))

                    UnaryHTTPRequest(
                        url = request.url,
                        contentType = request.contentType,
                        headers = requestHeaders,
                        message = request.message,
                        timeout = request.timeout,
                        methodSpec = request.methodSpec,
                        httpMethod = request.httpMethod
                    )
                } catch (t: Throwable) {
                    // responseFunction won't run, so clear the slot ourselves to
                    // avoid stale state leaking to the next call on this thread.
                    requestUrl.remove()
                    throw t
                }
            },
            responseFunction = { resp ->
                val url = requestUrl.get()
                requestUrl.remove()

                // Cache any server-issued DPoP nonce for future requests to the same origin
                val dpopNonce = resp.headers["dpop-nonce"]?.firstOrNull()
                    ?: resp.headers["DPoP-Nonce"]?.firstOrNull()
                if (dpopNonce != null && url != null) {
                    ts.cacheNonce(url, dpopNonce)
                }
                logger.debug("DPoP path=unary-response url={} nonceCached={} status={}",
                        url, dpopNonce != null && url != null, resp.status)
                resp
            },
        )
    }

    /**
     * Returns an OkHttp interceptor that retries on RFC 9449 §9 DPoP nonce challenges
     * from resource servers (KAS and the platform-services Connect client).
     * A 401 is retried only when WWW-Authenticate carries scheme=DPoP and error=use_dpop_nonce;
     * any other 401 (or any 401 with only a stray DPoP-Nonce header) is passed through unchanged.
     * The challenge is retried at most once: if the retried request is itself challenged, that
     * response is returned as-is rather than looping.
     * Rotated nonces are cached after every successful proceed so the next request picks them up.
     */
    fun dpopRetryInterceptor(): okhttp3.Interceptor = okhttp3.Interceptor { chain ->
        val url = chain.request().url.toUrl()
        val outgoingMethod = chain.request().method
        var response = chain.proceed(chain.request())

        // RFC 9449 §9: cache any rotated nonce from the response, regardless of status.
        cacheNonceIfPresent(url, response)

        logger.debug("DPoP path=okhttp url={} method={} status={} authScheme={} {}",
                url, outgoingMethod, response.code,
                authScheme(chain.request().header("Authorization")),
                dpopSummary(chain.request().header("DPoP")))

        if (response.code == 401 && isDpopNonceChallenge(response)) {
            val dpopNonce = response.header("dpop-nonce") ?: response.header("DPoP-Nonce")
            if (dpopNonce != null) {
                response.close()
                ts.cacheNonce(url, dpopNonce)
                val authHeaders = ts.getAuthHeaders(url, chain.request().method)
                val newRequestBuilder = chain.request().newBuilder()
                    .header("Authorization", authHeaders.authHeader)
                    .removeHeader("DPoP")
                // Re-add only when the refreshed token is still DPoP-bound. Without the
                // remove above, a Bearer downgrade would leave the original request's
                // stale DPoP proof paired with a Bearer Authorization header.
                authHeaders.dpopHeader?.let { newRequestBuilder.header("DPoP", it) }
                val newRequest = newRequestBuilder.build()
                logger.debug("DPoP path=okhttp-retry url={} method={} nonce={} authScheme={} {}",
                        url, chain.request().method, dpopNonce,
                        authScheme(authHeaders.authHeader), dpopSummary(authHeaders.dpopHeader))
                response = try {
                    chain.proceed(newRequest)
                } catch (e: Exception) {
                    logger.debug("DPoP retry request to {} failed", url, e)
                    throw e
                }
                cacheNonceIfPresent(url, response)
                logger.debug("DPoP path=okhttp-retry-response url={} status={}", url, response.code)
            } else {
                // RFC 9449 §9 requires the nonce alongside use_dpop_nonce. A challenge
                // without it is a server protocol violation; surface it rather than
                // passing a bare, unexplained 401 back to the caller (mirrors the
                // token-endpoint handling in TokenSource.getToken).
                logger.warn("DPoP nonce challenge from {} lacked a DPoP-Nonce header; passing 401 through", url)
            }
        }
        response
    }

    private fun cacheNonceIfPresent(url: URL, response: okhttp3.Response) {
        val nonce = response.header("dpop-nonce") ?: response.header("DPoP-Nonce")
        if (nonce != null) {
            ts.cacheNonce(url, nonce)
        }
    }

    private fun isDpopNonceChallenge(response: okhttp3.Response): Boolean {
        return response.challenges().any { challenge ->
            challenge.scheme.equals("DPoP", ignoreCase = true) &&
                challenge.authParams["error"].equals("use_dpop_nonce", ignoreCase = true)
        }
    }

    private fun authScheme(authHeader: String?): String {
        if (authHeader == null) return "<none>"
        val idx = authHeader.indexOf(' ')
        return if (idx > 0) authHeader.substring(0, idx) else "?"
    }

    private fun dpopSummary(dpopProof: String?): String {
        if (dpopProof == null) return "dpop=<absent>"
        return try {
            val claims = SignedJWT.parse(dpopProof).jwtClaimsSet
            "dpop[htm=${claims.getStringClaim("htm")} htu=${claims.getStringClaim("htu")}" +
                " jti=${claims.getStringClaim("jti")} nonce=${claims.getStringClaim("nonce")}]"
        } catch (e: Exception) {
            "dpop=<unparseable: ${e.message}>"
        }
    }
}
