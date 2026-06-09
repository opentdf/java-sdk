package io.opentdf.platform.sdk

import com.connectrpc.Interceptor
import com.connectrpc.StreamFunction
import com.connectrpc.UnaryFunction
import com.connectrpc.http.UnaryHTTPRequest
import com.connectrpc.http.clone
import java.net.URL

internal class AuthInterceptor(private val ts: TokenSource) : Interceptor {
    // Thread request URL from requestFunction into responseFunction for nonce caching
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
                requestUrl.set(request.url)

                val requestHeaders = mutableMapOf<String, List<String>>()
                val authHeaders = ts.getAuthHeaders(request.url, request.httpMethod.name)
                requestHeaders["Authorization"] = listOf(authHeaders.authHeader)
                requestHeaders["DPoP"] = listOf(authHeaders.dpopHeader)

                return@UnaryFunction UnaryHTTPRequest(
                    url = request.url,
                    contentType = request.contentType,
                    headers = requestHeaders,
                    message = request.message,
                    timeout = request.timeout,
                    methodSpec = request.methodSpec,
                    httpMethod = request.httpMethod
                )
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
     * Returns an OkHttp interceptor that retries on 401 responses carrying a DPoP-Nonce header.
     * The nonce is cached in the TokenSource and used in a fresh proof for the single retry.
     */
    fun dpopRetryInterceptor(): okhttp3.Interceptor = okhttp3.Interceptor { chain ->
        val response = chain.proceed(chain.request())
        if (response.code == 401) {
            val dpopNonce = response.header("dpop-nonce") ?: response.header("DPoP-Nonce")
            if (dpopNonce != null) {
                response.close()
                val url = chain.request().url.toUrl()
                val method = chain.request().method
                ts.cacheNonce(url, dpopNonce)
                val authHeaders = ts.getAuthHeaders(url, method)
                val newRequest = chain.request().newBuilder()
                    .header("Authorization", authHeaders.authHeader)
                    .header("DPoP", authHeaders.dpopHeader)
                    .build()
                return@Interceptor chain.proceed(newRequest)
            }
        }
        response
    }
}
