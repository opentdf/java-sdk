package io.opentdf.platform.sdk;

public class Assertion {

    public enum Type {
        HandlingAssertion("Handling"),
        BaseAssertion("Base");

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
        TrustedDataObj("TDO"),
        Payload("PAYL"),
        Explicit("EXPLICIT");

        private final String scope;

        Scope(String scope) {
            this.scope = scope;
        }
    }

    public enum AppliesToState {
        Encrypted("encrypted"),
        Unencrypted("unencrypted");

        private final String state;

        AppliesToState(String state) {
            this.state = state;
        }
    }

    public enum StatementFormat {
        ReferenceStatement("ReferenceStatement"),
        StructuredStatement("StructuredStatement"),
        StringStatement("StringStatement"),
        Base64BinaryStatement("Base64BinaryStatement"),
        XMLBase64("XMLBase64"),
        HandlingStatement("HandlingStatement"),
        StringType("String");

        private String format;

        StatementFormat(String format) {
            this.format = format;
        }
    }


    public enum BindingMethod {
        JWT("jwt");

        private String method;

        BindingMethod(String method) {
            this.method = method;
        }
    }

    static public class Statement {
        public String format;
        public String value;
    }

    static public class Binding {
        public String method;
        public String signature;
    }

    public String id;
    public String type;
    public String scope;
    public String appliesToState;
    public Statement statement;
    public Binding binding;
}