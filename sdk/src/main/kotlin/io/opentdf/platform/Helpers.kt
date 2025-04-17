package io.opentdf.platform.sdk

import com.connectrpc.UnaryBlockingCall
import com.connectrpc.getOrThrow
import io.opentdf.platform.policy.attributes.AttributesServiceClient
import io.opentdf.platform.policy.attributes.GetAttributeValuesByFqnsRequest
import io.opentdf.platform.policy.attributes.GetAttributeValuesByFqnsResponse
import io.opentdf.platform.policy.namespaces.GetNamespaceRequest
import io.opentdf.platform.policy.namespaces.NamespaceServiceClient
import kotlinx.coroutines.runBlocking

class Helpers {
    companion object {
        @JvmStatic
        fun <T> call(ub: UnaryBlockingCall<T>): T {
            return ub.execute().getOrThrow();
        }

        @JvmStatic
        fun <K, V> noHeaders(): Map<K, V> {
            return emptyMap()
        }

        @JvmStatic
        fun getNamespace(nsc: NamespaceServiceClient, req: GetNamespaceRequest) {
            return runBlocking {
                nsc.getNamespace(req, emptyMap()).getOrThrow();
            }
        }

        @JvmStatic
        fun getAttributeValuesByFqns(nsc: AttributesServiceClient, req: GetAttributeValuesByFqnsRequest): GetAttributeValuesByFqnsResponse {
            return nsc.getAttributeValuesByFqnsBlocking(req, emptyMap()).execute().getOrThrow();
        }
    }
}