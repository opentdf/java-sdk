package io.opentdf.platform.sdk;

import com.google.gson.annotations.SerializedName;

import java.util.List;

public class Manifest {
    static public class Segment {
        public String hash;
        public long segmentSize;
        public long encryptedSegmentSize;
    }

    static public class RootSignature {
        @SerializedName(value = "alg")
        public String algorithm;
        @SerializedName(value = "sig")
        public String signature;
    }

    static public class IntegrityInformation {
        public RootSignature rootSignature;
        public String segmentHashAlg;
        public int segmentSizeDefault;
        public int encryptedSegmentSizeDefault;
        public List<Segment> segments;
    }

    static public class KeyAccess {
        @SerializedName(value = "type")
        public String keyType;
        public String url;
        public String protocol;
        public String wrappedKey;
        public String policyBinding;
        public String encryptedMetadata;
        public String kid;
    }

    static public class Method {
        public String algorithm;
        public String iv;
        public Boolean IsStreamable;
    }

    static public class EncryptionInformation {
        @SerializedName(value = "type")
        public String keyAccessType;
        public String policy;

        @SerializedName(value = "keyAccess")
        public List<KeyAccess> keyAccessObj;
        public Method method;
        public IntegrityInformation integrityInformation;
    }

    static public class Payload {
        public String type;
        public String url;
        public String protocol;
        public String mimeType;
        public Boolean isEncrypted;
    }

    public EncryptionInformation encryptionInformation;
    public Payload payload;
    public  List<Assertion> assertions;
}
