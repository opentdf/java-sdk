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

        // Sign signs the assertion with the given hash and signature using the key.
        // It returns an error if the signing fails.
        // The assertion binding is updated with the method and the signature.
        public void sign(HashValues hashValues, AssertionConfig.AssertionKey assertionKey) throws KeyLengthException {
            var claims = new JWTClaimsSet.Builder()
                    .claim(kAssertionHash, hashValues.assertionHash)
                    .claim(kAssertionSignature, hashValues.signature)
                    .build();

            JWSHeader jws;
            JWSSigner signer;
            if (assertionKey.alg == AssertionConfig.AssertionKeyAlg.RS256) {
                jws = new JWSHeader.Builder(JWSAlgorithm.RS256).build();
                signer = new RSASSASigner((PrivateKey) assertionKey.key);
            } else if (assertionKey.alg == AssertionConfig.AssertionKeyAlg.HS256) {
                jws = new JWSHeader.Builder(JWSAlgorithm.HS256).build();
                signer = new MACSigner((byte[])assertionKey.key);
            } else {
                throw new SDKException("unknown assertion key algorithm, error signing assertion");
            }

            SignedJWT jwt = new SignedJWT(jws, claims);
            try {
                jwt.sign(signer);
            } catch (JOSEException e) {
                throw new SDKException("error signing assertion", e);
            }

            this.binding = new Binding();
            this.binding.method = AssertionConfig.BindingMethod.JWS.name();
            this.binding.signature = jwt.serialize();
        }

        public Assertion.HashValues verify(AssertionConfig.AssertionKey assertionKey) throws ParseException, IOException, JOSEException {
            var binding = this.binding;
            this.binding = null;

            SignedJWT signedJWT = SignedJWT.parse(binding.signature);
            JWSVerifier verifier;
            if (assertionKey.alg == AssertionConfig.AssertionKeyAlg.RS256) {
                verifier = new RSASSAVerifier((RSAPublicKey)assertionKey.key);
            } else if (assertionKey.alg == AssertionConfig.AssertionKeyAlg.HS256) {
                verifier = new MACVerifier((byte[])assertionKey.key);
            } else {
                throw new SDKException("Unknown verify key, unable to verify assertion signature");
            }

            if (!signedJWT.verify(verifier)) {
                throw new SDKException("Unable to verify assertion signature");
            }

            var assertionHash = signedJWT.getJWTClaimsSet().getStringClaim(kAssertionHash);
            var signature = signedJWT.getJWTClaimsSet().getStringClaim(kAssertionSignature);

            return new HashValues(assertionHash, signature);
        }
    }

        // Verify checks the binding signature of the assertion and
// returns the hash and the signature. It returns an error if the verification fails.
//        func (a Assertion) Verify(key AssertionKey) (string, string, error) {
//            tok, err := jwt.Parse([]byte(a.Binding.Signature),
//                    jwt.WithKey(jwa.KeyAlgorithmFrom(key.Alg.String()), key.Key),
//	)
//            if err != nil {
//                return "", "", err
//            }
//            hashClaim, found := tok.Get(kAssertionHash)
//            if !found {
//                return "", "", fmt.Errorf("hash claim not found")
//            }
//            hash, ok := hashClaim.(string)
//            if !ok {
//                return "", "", fmt.Errorf("hash claim is not a string")
//            }
//
//            sigClaim, found := tok.Get(kAssertionSignature)
//            if !found {
//                return "", "", fmt.Errorf("signature claim not found")
//            }
//            sig, ok := sigClaim.(string)
//            if !ok {
//                return "", "", fmt.Errorf("signature claim is not a string")
//            }
//            return hash, sig, nil
//        }
//    }

    public EncryptionInformation encryptionInformation;
    public Payload payload;
    public  List<Assertion> assertions = new ArrayList<>();
}
