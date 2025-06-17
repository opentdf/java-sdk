package io.opentdf.platform.sdk;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Objects;

/**
 * Represents the configuration for assertions, encapsulating various types,
 * scopes, states, keys,
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
        final String tdfSpecVersion;

        @SerializedName("creation_date")
        final String creationDate;

        @SerializedName("operating_system")
        final String operatingSystem;

        @SerializedName("sdk_version")
        final String sdkVersion;

        @SerializedName("java_version") // Corresponds to "go_version" in the Go example
        final String javaVersion;

        @SerializedName("architecture")
        final String architecture;

        SystemMetadata(String tdfSpecVersion, String creationDate, String operatingSystem,
                String sdkVersion, String javaVersion, String architecture) {
            this.tdfSpecVersion = tdfSpecVersion;
            this.creationDate = creationDate;
            this.operatingSystem = operatingSystem;
            this.sdkVersion = sdkVersion;
            this.javaVersion = javaVersion;
            this.architecture = architecture;
        }
    }

    /**
     * Returns a default assertion configuration with predefined system metadata.
     * This method mimics the behavior of the Go function
     * GetSystemMetadataAssertionConfig.
     *
     * @param tdfSpecVersionFromSDK The TDF specification version (e.g., "4.3.0").
     * @param sdkInternalVersion    The internal version of this SDK (e.g.,
     *                              "1.0.0"), which will be prefixed with "Java-".
     * @return An {@link AssertionConfig} populated with system metadata.
     * @throws SDKException if there's an error marshalling the metadata to JSON.
     */
    public static AssertionConfig getSystemMetadataAssertionConfig(String tdfSpecVersionFromSDK) {
        String creationDate = OffsetDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
        String operatingSystem = System.getProperty("os.name");
        String sdkVersion = "Java-" + Version.SDK;
        String javaVersion = System.getProperty("java.version");
        String architecture = System.getProperty("os.arch");

        SystemMetadata metadata = new SystemMetadata(tdfSpecVersionFromSDK, creationDate, operatingSystem,
                sdkVersion, javaVersion, architecture);

        Gson gson = new Gson(); // A new Gson instance is used for simplicity here.
        String metadataJSON;
        try {
            metadataJSON = gson.toJson(metadata);
        } catch (com.google.gson.JsonIOException | com.google.gson.JsonSyntaxException e) {
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