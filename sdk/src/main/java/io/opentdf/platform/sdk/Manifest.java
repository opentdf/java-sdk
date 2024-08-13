package io.opentdf.platform.sdk;

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class Manifest {
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

    public EncryptionInformation encryptionInformation;
    public Payload payload;
    public  List<Assertion> assertions = new ArrayList<>();
}
