package io.opentdf.platform.sdk;

/**
 * Exception thrown when automatic configuration fails.
 */
public class AutoConfigureException extends RuntimeException  {
    public AutoConfigureException(String message) {
        super(message);
    }

    public AutoConfigureException(Exception e) {
        super(e);
    }

    public AutoConfigureException(String message, Exception e) {
        super(message, e);
    }
}
