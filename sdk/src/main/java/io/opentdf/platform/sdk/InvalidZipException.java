package io.opentdf.platform.sdk;

/**
 * InvalidZipException is thrown to indicate that a ZIP file being read
 * is invalid or corrupted in some way. This exception extends RuntimeException,
 * allowing it to be thrown during the normal operation of the Java Virtual Machine.
 */
public class InvalidZipException extends RuntimeException {
    public InvalidZipException(String message) {
        super(message);
    }
}
