package io.opentdf.platform.sdk;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;

public class Config {

    public static final int TDF3_KEY_SIZE = 2048;
    public static final int DEFAULT_SEGMENT_SIZE = 2 * 1024 * 1024; // 2mb
    public static final String KAS_PUBLIC_KEY_PATH = "/kas_public_key";

    public enum TDFFormat {
        JSONFormat,
        XMLFormat
    }

    public enum IntegrityAlgorithm {
        HS256,
        GMAC
    }

    public static final int K_HTTP_OK = 200;

    public static class KASInfo {
        public String URL;
        public String PublicKey;
    }

    public static class TDFConfig {
        public int defaultSegmentSize;
        public boolean enableEncryption;
        public TDFFormat tdfFormat;
        public String tdfPublicKey;
        public String tdfPrivateKey;
        public String metaData;
        public IntegrityAlgorithm integrityAlgorithm;
        public IntegrityAlgorithm segmentIntegrityAlgorithm;
        public List<String> attributes;
        public List<KASInfo> kasInfoList;

        public TDFConfig() {
            this.defaultSegmentSize = DEFAULT_SEGMENT_SIZE;
            this.enableEncryption = true;
            this.tdfFormat = TDFFormat.JSONFormat;
            this.integrityAlgorithm = IntegrityAlgorithm.HS256;
            this.segmentIntegrityAlgorithm = IntegrityAlgorithm.GMAC;
            this.attributes = new ArrayList<>();
            this.kasInfoList = new ArrayList<>();
        }
    }

    @SafeVarargs
    public static TDFConfig newTDFConfig(Consumer<TDFConfig>... options) {
        TDFConfig config = new TDFConfig();
        for (Consumer<TDFConfig> option : options) {
            option.accept(config);
        }
        return config;
    }

    public static Consumer<TDFConfig> withDataAttributes(String... attributes) {
        return (TDFConfig config) -> {
            Collections.addAll(config.attributes, attributes);
        };
    }

    public static Consumer<TDFConfig> withKasInformation(KASInfo... kasInfoList) {
        return (TDFConfig config) -> {
            Collections.addAll(config.kasInfoList, kasInfoList);
        };
    }

    public static Consumer<TDFConfig> withMetaData(String metaData) {
        return (TDFConfig config) -> config.metaData = metaData;
    }

    public static Consumer<TDFConfig> withSegmentSize(int size) {
        return (TDFConfig config) -> config.defaultSegmentSize = size;
    }
}