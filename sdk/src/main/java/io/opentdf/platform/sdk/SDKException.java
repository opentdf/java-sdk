package io.opentdf.platform.sdk;

/**
 * SDKException serves as a custom exception class for handling errors
 * specific to the SDK's operations and processes. It extends
 * RuntimeException, making it an unchecked exception.
 */
public class SDKException extends RuntimeException {
    public SDKException(String message, Exception reason) {
        super(message, reason);
    }

    public SDKException(String message) {
        super(message);
    }
}
