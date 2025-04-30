package io.opentdf.platform.sdk

import com.connectrpc.ConnectException
import com.connectrpc.ResponseMessage
import com.connectrpc.getOrThrow

class RequestHelper {
    companion object {
        /**
         * Kotlin doesn't have checked exceptions so that if we want to catch
         * an exception thrown by Kotlin we need to declare that the method throws it.
         * ResponseMessageKt.getOrThrow() doesn't do so; so we need to wrap it
         */
        @JvmStatic @Throws(ConnectException::class)
        fun <T> getOrThrow(responseMessage: ResponseMessage<T>): T {
            return responseMessage.getOrThrow();
        }
    }
}