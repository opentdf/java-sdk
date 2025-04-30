package io.opentdf.platform.sdk

import com.connectrpc.ConnectException
import com.connectrpc.ResponseMessage
import com.connectrpc.getOrThrow

class RequestHelper {
    companion object {
        /**
         * Kotlin doesn't have checked exceptions (importantly it doesn't declare them).
         *  This means that if a Kotlin function throws a checked exception, you can't
         *  catch it in Java unless it uses the {@class kotlin.jvm.Throws} annotation.
         *  We wrap the getOrThrow() method in a static method with the annotation we
         *  need to catch a {@class ConnectException} in Java.
         */
        @JvmStatic @Throws(ConnectException::class)
        fun <T> getOrThrow(responseMessage: ResponseMessage<T>): T {
            return responseMessage.getOrThrow();
        }
    }
}