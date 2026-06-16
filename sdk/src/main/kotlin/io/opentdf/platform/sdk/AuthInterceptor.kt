package io.opentdf.platform.sdk

import com.connectrpc.Interceptor
import com.connectrpc.StreamFunction
import com.connectrpc.UnaryFunction
import com.connectrpc.http.UnaryHTTPRequest
import com.connectrpc.http.clone
import java.net.URL

internal class AuthInterceptor(private val ts: TokenSource) : Interceptor {
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
                requestHeaders["DPoP"] = listOf(authHeaders.dpopHeader)

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
                    requestHeaders["DPoP"] = listOf(authHeaders.dpopHeader)

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
                resp
            },
        )
    }

    /**
     * Returns an OkHttp interceptor that retries on RFC 9449 §8 DPoP nonce challenges.
     * A 401 is retried only when WWW-Authenticate carries scheme=DPoP and error=use_dpop_nonce;
     * any other 401 (or any 401 with only a stray DPoP-Nonce header) is passed through unchanged.
     * Rotated nonces are cached after every successful proceed so the next request picks them up.
     */
    fun dpopRetryInterceptor(): okhttp3.Interceptor = okhttp3.Interceptor { chain ->
        val url = chain.request().url.toUrl()
        var response = chain.proceed(chain.request())

        // RFC 9449 §8.1: cache any rotated nonce from the response, regardless of status.
        cacheNonceIfPresent(url, response)

        if (response.code == 401 && isDpopNonceChallenge(response)) {
            val dpopNonce = response.header("dpop-nonce") ?: response.header("DPoP-Nonce")
            if (dpopNonce != null) {
                response.close()
                ts.cacheNonce(url, dpopNonce)
                val authHeaders = ts.getAuthHeaders(url, chain.request().method)
                val newRequest = chain.request().newBuilder()
                    .header("Authorization", authHeaders.authHeader)
                    .header("DPoP", authHeaders.dpopHeader)
                    .build()
                response = chain.proceed(newRequest)
                cacheNonceIfPresent(url, response)
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
}
