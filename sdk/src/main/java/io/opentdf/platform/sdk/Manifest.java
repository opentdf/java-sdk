package io.opentdf.platform.sdk;

import com.google.gson.annotations.SerializedName;

public class Manifest {
    public static class KeyAccess {
        @SerializedName("type")
        String keyType;
        @SerializedName("url")
        String kasUrl;
        String protocol;
        String wrappedKey;
        String policyBinding;
        String encryptedMetadata;
    }
}
