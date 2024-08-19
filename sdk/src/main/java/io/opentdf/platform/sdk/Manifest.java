package io.opentdf.platform.sdk;

import com.google.gson.*;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.binary.Hex;
import org.erdtman.jcs.JsonCanonicalizer;

import java.io.IOException;
import java.lang.reflect.Type;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

public class Manifest {

    private static final String kAssertionHash = "assertionHash";
    private static final String kAssertionSignature = "assertionSig";

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Manifest manifest = (Manifest) o;
        return Objects.equals(encryptionInformation, manifest.encryptionInformation) && Objects.equals(payload, manifest.payload) && Objects.equals(assertions, manifest.assertions);
    }

    @Override
    public int hashCode() {
        return Objects.hash(encryptionInformation, payload, assertions);
    }

    private static class PolicyBindingSerializer implements JsonDeserializer<Object>, JsonSerializer<Object> {
        @Override
        public Object deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
            if (json.isJsonObject()) {
                return context.deserialize(json, Manifest.PolicyBinding.class);
            } else if (json.isJsonPrimitive() && json.getAsJsonPrimitive().isString()) {
                return json.getAsString();
            } else {
                throw new JsonParseException("Unexpected type for policyBinding");
            }
        }

        @Override
        public JsonElement serialize(Object src, Type typeOfSrc, JsonSerializationContext context) {
            return context.serialize(src, typeOfSrc);
        }
    }
    static public class Segment {
        public String hash;
        public long segmentSize;
        public long encryptedSegmentSize;

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Segment segment = (Segment) o;
            return segmentSize == segment.segmentSize && encryptedSegmentSize == segment.encryptedSegmentSize && Objects.equals(hash, segment.hash);
        }

        @Override
        public int hashCode() {
            return Objects.hash(hash, segmentSize, encryptedSegmentSize);
        }
    }

    static public class RootSignature {
        @SerializedName(value = "alg")
        public String algorithm;
        @SerializedName(value = "sig")
        public String signature;

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            RootSignature that = (RootSignature) o;
            return Objects.equals(algorithm, that.algorithm) && Objects.equals(signature, that.signature);
        }

        @Override
        public int hashCode() {
            return Objects.hash(algorithm, signature);
        }
    }

    static public class IntegrityInformation {
        public RootSignature rootSignature;
        public String segmentHashAlg;
        public int segmentSizeDefault;
        public int encryptedSegmentSizeDefault;
        public List<Segment> segments;

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            IntegrityInformation that = (IntegrityInformation) o;
            return segmentSizeDefault == that.segmentSizeDefault && encryptedSegmentSizeDefault == that.encryptedSegmentSizeDefault && Objects.equals(rootSignature, that.rootSignature) && Objects.equals(segmentHashAlg, that.segmentHashAlg) && Objects.equals(segments, that.segments);
        }

        @Override
        public int hashCode() {
            return Objects.hash(rootSignature, segmentHashAlg, segmentSizeDefault, encryptedSegmentSizeDefault, segments);
        }
    }
    
    static public class PolicyBinding {
        public String alg;
        public String hash;

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            PolicyBinding that = (PolicyBinding) o;
            return Objects.equals(alg, that.alg) && Objects.equals(hash, that.hash);
        }

        @Override
        public int hashCode() {
            return Objects.hash(alg, hash);
        }
    }

    static public class KeyAccess {
        @SerializedName(value = "type")
        public String keyType;
        public String url;
        public String protocol;
        public String wrappedKey;
        @JsonAdapter(PolicyBindingSerializer.class)
        public Object policyBinding;

        public String encryptedMetadata;
        public String kid;
        public String sid;

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            KeyAccess keyAccess = (KeyAccess) o;
            return Objects.equals(keyType, keyAccess.keyType) && Objects.equals(url, keyAccess.url) && Objects.equals(protocol, keyAccess.protocol) && Objects.equals(wrappedKey, keyAccess.wrappedKey) && Objects.equals(policyBinding, keyAccess.policyBinding) && Objects.equals(encryptedMetadata, keyAccess.encryptedMetadata) && Objects.equals(kid, keyAccess.kid);
        }

        @Override
        public int hashCode() {
            return Objects.hash(keyType, url, protocol, wrappedKey, policyBinding, encryptedMetadata, kid);
        }
    }

    static public class Method {
        public String algorithm;
        public String iv;
        public Boolean IsStreamable;

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Method method = (Method) o;
            return Objects.equals(algorithm, method.algorithm) && Objects.equals(iv, method.iv) && Objects.equals(IsStreamable, method.IsStreamable);
        }

        @Override
        public int hashCode() {
            return Objects.hash(algorithm, iv, IsStreamable);
        }
    }

    

    static public class EncryptionInformation {
        @SerializedName(value = "type")
        public String keyAccessType;
        public String policy;

        @SerializedName(value = "keyAccess")
        public List<KeyAccess> keyAccessObj;
        public Method method;
        public IntegrityInformation integrityInformation;

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            EncryptionInformation that = (EncryptionInformation) o;
            return Objects.equals(keyAccessType, that.keyAccessType) && Objects.equals(policy, that.policy) && Objects.equals(keyAccessObj, that.keyAccessObj) && Objects.equals(method, that.method) && Objects.equals(integrityInformation, that.integrityInformation);
        }

        @Override
        public int hashCode() {
            return Objects.hash(keyAccessType, policy, keyAccessObj, method, integrityInformation);
        }
    }

    static public class Payload {
        public String type;
        public String url;
        public String protocol;
        public String mimeType;
        public Boolean isEncrypted;

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Payload payload = (Payload) o;
            return Objects.equals(type, payload.type) && Objects.equals(url, payload.url) && Objects.equals(protocol, payload.protocol) && Objects.equals(mimeType, payload.mimeType) && Objects.equals(isEncrypted, payload.isEncrypted);
        }

        @Override
        public int hashCode() {
            return Objects.hash(type, url, protocol, mimeType, isEncrypted);
        }
    }

    static public class Binding {
        public String method;
        public String signature;

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Binding binding = (Binding) o;
            return Objects.equals(method, binding.method) && Objects.equals(signature, binding.signature);
        }

        @Override
        public int hashCode() {
            return Objects.hash(method, signature);
        }
    }

    static public class Assertion {
        public String id;
        public String type;
        public String scope;
        public String appliesToState;
        public AssertionConfig.Statement statement;
        public Binding binding;

        static public class HashValues {
            private final String assertionHash;
            private final String signature;

            public HashValues(String assertionHash, String signature) {
                this.assertionHash = assertionHash;
                this.signature = signature;
            }

            public String getAssertionHash() { return assertionHash; }
            public String getSignature() { return signature; }
        }


        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Assertion that = (Assertion) o;
            return Objects.equals(id, that.id) && Objects.equals(type, that.type) &&
                    Objects.equals(scope, that.scope) && Objects.equals(appliesToState, that.appliesToState) &&
                    Objects.equals(statement, that.statement) && Objects.equals(binding, that.binding);
        }

        @Override
        public int hashCode() {
            return Objects.hash(id, type, scope, appliesToState, statement, binding);
        }

        public String hash() throws IOException {
            Gson gson = new Gson();
            MessageDigest digest;
            try {
                digest = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                throw new SDKException("error creating SHA-256 message digest", e);
            }

            var assertionAsJson = gson.toJson(this);
            JsonCanonicalizer jc = new JsonCanonicalizer(assertionAsJson);
            return Hex.encodeHexString(digest.digest(jc.getEncodedUTF8()));
        }

        // Sign the assertion with the given hash and signature using the key.
        // It returns an error if the signing fails.
        // The assertion binding is updated with the method and the signature.
        public void sign(final HashValues hashValues, final AssertionConfig.AssertionKey assertionKey) throws KeyLengthException {
            // Build JWT claims
            final JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .claim(kAssertionHash, hashValues.assertionHash)
                    .claim(kAssertionSignature, hashValues.signature)
                    .build();

            // Prepare for signing
            SignedJWT signedJWT = createSignedJWT(claims, assertionKey);

            try {
                // Sign the JWT
                signedJWT.sign(createSigner(assertionKey));
            } catch (JOSEException e) {
                throw new SDKException("Error signing assertion", e);
            }

            // Store the binding and signature
            this.binding = new Binding();
            this.binding.method = AssertionConfig.BindingMethod.JWS.name();
            this.binding.signature = signedJWT.serialize();
        }

        // Checks the binding signature of the assertion and
        // returns the hash and the signature. It returns an error if the verification fails.
        public Assertion.HashValues verify(AssertionConfig.AssertionKey assertionKey) throws ParseException, JOSEException {
            if (binding == null) {
                throw new SDKException("Binding is null in assertion");
            }

            String signatureString = binding.signature;
            binding = null; // Clear the binding after use

            SignedJWT signedJWT = SignedJWT.parse(signatureString);
            JWSVerifier verifier = createVerifier(assertionKey);

            if (!signedJWT.verify(verifier)) {
                throw new SDKException("Unable to verify assertion signature");
            }

            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            String assertionHash = claimsSet.getStringClaim(kAssertionHash);
            String signature = claimsSet.getStringClaim(kAssertionSignature);

            return new Assertion.HashValues(assertionHash, signature);
        }

        private SignedJWT createSignedJWT(final JWTClaimsSet claims, final AssertionConfig.AssertionKey assertionKey) throws SDKException {
            final JWSHeader jwsHeader;
            switch (assertionKey.alg) {
                case RS256:
                    jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).build();
                    break;
                case HS256:
                    jwsHeader = new JWSHeader.Builder(JWSAlgorithm.HS256).build();
                    break;
                default:
                    throw new SDKException("Unknown assertion key algorithm, error signing assertion");
            }

            return new SignedJWT(jwsHeader, claims);
        }

        private JWSSigner createSigner(final AssertionConfig.AssertionKey assertionKey) throws SDKException, KeyLengthException {
            switch (assertionKey.alg) {
                case RS256:
                    if (!(assertionKey.key instanceof PrivateKey)) {
                        throw new SDKException("Expected PrivateKey for RS256 algorithm");
                    }
                    return new RSASSASigner((PrivateKey) assertionKey.key);
                case HS256:
                    if (!(assertionKey.key instanceof byte[])) {
                        throw new SDKException("Expected byte[] key for HS256 algorithm");
                    }
                    return new MACSigner((byte[]) assertionKey.key);
                default:
                    throw new SDKException("Unknown signing algorithm: " + assertionKey.alg);
            }
        }

        private JWSVerifier createVerifier(AssertionConfig.AssertionKey assertionKey) throws JOSEException {
            switch (assertionKey.alg) {
                case RS256:
                    return new RSASSAVerifier((RSAPublicKey) assertionKey.key);
                case HS256:
                    return new MACVerifier((byte[]) assertionKey.key);
                default:
                    throw new SDKException("Unknown verify key, unable to verify assertion signature");
            }
        }
    }

    public EncryptionInformation encryptionInformation;
    public Payload payload;
    public  List<Assertion> assertions = new ArrayList<>();
}
