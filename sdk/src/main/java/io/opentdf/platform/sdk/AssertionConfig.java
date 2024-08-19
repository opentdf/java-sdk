package io.opentdf.platform.sdk;

import com.nimbusds.jose.JWSSigner;

import java.util.Objects;


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
    }

    public enum BindingMethod {
        JWS("jws");

        private String method;

        BindingMethod(String method) {
            this.method = method;
        }
    }

    static public class AssertionKey {
        public Object key;
        public AssertionKeyAlg alg = AssertionKeyAlg.NotDefined;

        public AssertionKey(AssertionKeyAlg alg, Object key) {
            this.alg = alg;
            this.key = key;
        }

        public boolean isDefined()  {
            return alg != AssertionKeyAlg.NotDefined;
        }
    }

    static public class Statement {
        public String format;
        public String schema;
        public String value;

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Statement statement = (Statement) o;
            return Objects.equals(format, statement.format) && Objects.equals(schema, statement.schema) && Objects.equals(value, statement.value);
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
    public AssertionKey assertionKey;
}