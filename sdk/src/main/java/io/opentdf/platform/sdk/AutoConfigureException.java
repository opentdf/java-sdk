package io.opentdf.platform.sdk;

/**
 * Exception thrown when automatic configuration fails.
 */
public class AutoConfigureException extends SDKException {
    public AutoConfigureException(String message) {
        super(message);
    }
    public AutoConfigureException(String message, Exception cause) {
        super(message, cause);
    }
}
