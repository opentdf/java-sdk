package io.opentdf.platform.sdk;

public class SDKException extends RuntimeException {
    public SDKException(String message, Exception reason) {
        super(message, reason);
    }
}
