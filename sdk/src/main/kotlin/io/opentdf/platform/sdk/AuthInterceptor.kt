package io.opentdf.platform.sdk

import com.connectrpc.Interceptor
import com.connectrpc.StreamFunction
import com.connectrpc.UnaryFunction
import com.connectrpc.http.UnaryHTTPRequest
import com.connectrpc.http.clone

private class AuthInterceptor(private val ts: TokenSource) : Interceptor{
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
                resp
            },
        )
    }
}