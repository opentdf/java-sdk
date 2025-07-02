package io.opentdf.platform.sdk;

import com.connectrpc.ResponseMessage;
import com.connectrpc.UnaryBlockingCall;

import java.util.Collections;

public class TestUtil {
    static <T> UnaryBlockingCall<T> successfulUnaryCall(T result) {
        return new UnaryBlockingCall<T>() {
            @Override
            public ResponseMessage<T> execute() {
                return new ResponseMessage.Success<>(result, Collections.emptyMap(), Collections.emptyMap());
            }

            @Override
            public void cancel() {

            }
        };
    }
}
