package io.opentdf.platform.sdk;


import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Objects;

/**
 * Represents the configuration for assertions, encapsulating various types, scopes, states, keys,
 * and statements involved in assertion handling.
 */
public class AssertionConfig {

    public enum Type {
        HandlingAssertion("handling"),
        BaseAssertion("base");

        private final String type;

        Type(String assertionType) {
            this.type = assertionType;
        }

        @Override
        public String toString() {
            return type;
        }
    }

    public enum Scope {
        TrustedDataObj("tdo"),
        Payload("payload");

        private final String scope;

        Scope(String scope) {
            this.scope = scope;
        }

        @Override
        public String toString() {
            return scope;
        }
    }

    public enum AssertionKeyAlg {
        RS256,
        HS256,
        NotDefined;
    }

    public enum AppliesToState {
        Encrypted("encrypted"),
        Unencrypted("unencrypted");

        private final String state;

        AppliesToState(String state) {
            this.state = state;
        }

        @Override
        public String toString() {
            return state;
        }
    }

    public enum BindingMethod {
        JWS("jws");

        private String method;

        BindingMethod(String method) {
            this.method = method;
        }

        @Override
        public String toString() {
            return method;
        }
    }

    static public class AssertionKey {
        public Object key;
        public AssertionKeyAlg alg = AssertionKeyAlg.NotDefined;

        public AssertionKey(AssertionKeyAlg alg, Object key) {
            this.alg = alg;
            this.key = key;
        }

        public boolean isDefined() {
            return alg != AssertionKeyAlg.NotDefined;
        }
    }

    static public class Statement {
        public String format;
        public String schema;
        public String value;

        @Override
        public boolean equals(Object o) {
            if (this == o)
                return true;
            if (o == null || getClass() != o.getClass())
                return false;
            Statement statement = (Statement) o;
            return Objects.equals(format, statement.format) && Objects.equals(schema, statement.schema)
                    && Objects.equals(value, statement.value);
        }

        @Override
        public int hashCode() {
            return Objects.hash(format, schema, value);
        }
    }

    public String id;
    public Type type;
    public Scope scope;
    public AppliesToState appliesToState;
    public Statement statement;
    public AssertionKey signingKey;

    /**
     * Inner class to hold system metadata for assertion.
     * Fields are named to match the JSON output of the original Go function.
     */
    static private class SystemMetadata {
        @SerializedName("tdf_spec_version")
        String tdfSpecVersion;

        @SerializedName("creation_date")
        String creationDate;

        @SerializedName("operating_system")
        String operatingSystem;

        @SerializedName("sdk_version")
        String sdkVersion;

        @SerializedName("hostname")
        String hostname;

        @SerializedName("java_version") // Corresponds to "go_version" in the Go example
        String javaVersion;

        @SerializedName("architecture")
        String architecture;
    }

    /**
     * Returns a default assertion configuration with predefined system metadata.
     * This method mimics the behavior of the Go function GetSystemMetadataAssertionConfig.
     *
     * @param tdfSpecVersionFromSDK The TDF specification version (e.g., "4.3.0").
     * @param sdkInternalVersion    The internal version of this SDK (e.g., "1.0.0"), which will be prefixed with "Java-".
     * @return An {@link AssertionConfig} populated with system metadata.
     * @throws SDKException if there's an error marshalling the metadata to JSON.
     */
    public static AssertionConfig getSystemMetadataAssertionConfig(String tdfSpecVersionFromSDK, String sdkInternalVersion) {
        SystemMetadata metadata = new SystemMetadata();
        metadata.tdfSpecVersion = tdfSpecVersionFromSDK;
        metadata.creationDate = OffsetDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
        metadata.operatingSystem = System.getProperty("os.name");
        metadata.sdkVersion = "Java-" + sdkInternalVersion;
        metadata.javaVersion = System.getProperty("java.version");
        metadata.architecture = System.getProperty("os.arch");

        try {
            metadata.hostname = InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException e) {
            // Mimic Go behavior: if hostname retrieval fails, it's omitted.
            // Gson will omit null fields by default.
            // Optionally, log this exception: e.g., logger.warn("Could not retrieve hostname", e);
        }

        Gson gson = new Gson(); // A new Gson instance is used for simplicity here.
        String metadataJSON;
        try {
            metadataJSON = gson.toJson(metadata);
        } catch (Exception e) { // Catch general exception from Gson, though it's usually for I/O or reflection issues.
            throw new SDKException("Failed to marshal system metadata to JSON", e);
        }

        AssertionConfig config = new AssertionConfig();
        config.id = "default-assertion";
        config.type = Type.BaseAssertion;
        config.scope = Scope.Payload; // Maps from Go's PayloadScope
        config.appliesToState = AppliesToState.Unencrypted;

        Statement statement = new Statement();
        statement.format = "json";
        statement.schema = "metadata";
        statement.value = metadataJSON;
        config.statement = statement;

        return config;
    }
}