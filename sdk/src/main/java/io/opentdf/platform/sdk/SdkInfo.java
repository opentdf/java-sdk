package io.opentdf.platform.sdk;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Provides information about the SDK, such as its version.
 * The version is read from a properties file populated during the Maven build
 * process.
 */
public final class SdkInfo {
    private static final Logger logger = LoggerFactory.getLogger(SdkInfo.class);
    private static final String VERSION_PROPERTIES_FILE = "version.properties"; // Relative to this class's package
    private static final String SDK_VERSION_PROPERTY = "sdk.version";

    public static final String VERSION;

    static {
        String versionString = "unknown"; // Default if properties can't be read
        Properties props = new Properties();
        try (InputStream input = SdkInfo.class.getResourceAsStream(VERSION_PROPERTIES_FILE)) {
            if (input == null) {
                logger.error("Unable to find " + VERSION_PROPERTIES_FILE
                        + ". SDK version will be 'unknown'. Ensure it's in src/main/resources/io/opentdf/platform/sdk/");
            } else {
                props.load(input);
                versionString = props.getProperty(SDK_VERSION_PROPERTY, "unknown");
            }
        } catch (IOException ex) {
            logger.error("Error loading " + VERSION_PROPERTIES_FILE + ". SDK version will be 'unknown'.", ex);
        }
        VERSION = versionString;
        logger.info("OpenTDF SDK Version: {}", VERSION);
    }

    private SdkInfo() {
        // Private constructor to prevent instantiation of this utility class
    }
}