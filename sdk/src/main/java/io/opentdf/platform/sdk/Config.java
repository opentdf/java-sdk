package io.opentdf.platform.sdk;

import io.opentdf.platform.sdk.nanotdf.ECCMode;
import io.opentdf.platform.sdk.nanotdf.NanoTDFType;
import io.opentdf.platform.sdk.nanotdf.SymmetricAndPayloadConfig;

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

    public static class NanoTDFConfig {
        public ECCMode eccMode;
        public NanoTDFType.Cipher cipher;
        public SymmetricAndPayloadConfig config;
        public List<String> attributes;
        public List<KASInfo> kasInfoList;

        public NanoTDFConfig() {
            this.eccMode = new ECCMode();
            this.eccMode.setEllipticCurve(NanoTDFType.ECCurve.SECP256R1);
            this.eccMode.setECDSABinding(false);

            this.cipher = NanoTDFType.Cipher.AES_256_GCM_96_TAG;

            this.config = new SymmetricAndPayloadConfig();
            this.config.setHasSignature(false);
            this.config.setSymmetricCipherType(NanoTDFType.Cipher.AES_256_GCM_96_TAG);

            this.attributes = new ArrayList<>();
            this.kasInfoList = new ArrayList<>();
        }
    }

    public static NanoTDFConfig newNanoTDFConfig(Consumer<NanoTDFConfig>... options) {
        NanoTDFConfig config = new NanoTDFConfig();
        for (Consumer<NanoTDFConfig> option : options) {
            option.accept(config);
        }
        return config;
    }

    public static Consumer<NanoTDFConfig> witDataAttributes(String... attributes) {
        return (NanoTDFConfig config) -> {
            Collections.addAll(config.attributes, attributes);
        };
    }

    public static Consumer<NanoTDFConfig> withNanoKasInformation(KASInfo... kasInfoList) {
        return (NanoTDFConfig config) -> {
            Collections.addAll(config.kasInfoList, kasInfoList);
        };
    }

    public static Consumer<NanoTDFConfig> withEllipticCurve(String curve) {
        NanoTDFType.ECCurve ecCurve;
        if (curve == null || curve.isEmpty()) {
            ecCurve = NanoTDFType.ECCurve.SECP256R1; // default curve
        } else if (curve.compareToIgnoreCase(NanoTDFType.ECCurve.SECP384R1.toString()) == 0) {
            ecCurve = NanoTDFType.ECCurve.SECP384R1;
        } else if (curve.compareToIgnoreCase(NanoTDFType.ECCurve.SECP521R1.toString()) == 0) {
            ecCurve = NanoTDFType.ECCurve.SECP521R1;
        } else if (curve.compareToIgnoreCase(NanoTDFType.ECCurve.SECP256R1.toString()) == 0) {
            ecCurve = NanoTDFType.ECCurve.SECP256R1;
        } else {
            throw new IllegalArgumentException("The supplied curve string " + curve + " is not recognized.");
        }
        return (NanoTDFConfig config) -> config.eccMode.setEllipticCurve(ecCurve);
    }

    public static Consumer<NanoTDFConfig> WithECDSAPolicyBinding() {
        return (NanoTDFConfig config) -> config.eccMode.setECDSABinding(false);
    }
}