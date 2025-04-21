package io.opentdf.platform.sdk;

import io.opentdf.platform.generated.policy.Value;
import io.opentdf.platform.sdk.Autoconfigure.AttributeValueFQN;
import io.opentdf.platform.sdk.nanotdf.ECCMode;
import io.opentdf.platform.sdk.nanotdf.Header;
import io.opentdf.platform.sdk.nanotdf.NanoTDFType;
import io.opentdf.platform.sdk.nanotdf.SymmetricAndPayloadConfig;

import java.util.*;
import java.util.function.Consumer;

/**
 * Configuration class for setting various configurations related to TDF.
 * Contains nested classes and enums for specific configuration settings.
 */
public class Config {

    public static final int TDF3_KEY_SIZE = 2048;
    public static final int DEFAULT_SEGMENT_SIZE = 2 * 1024 * 1024; // 2mb
    public static final int MAX_SEGMENT_SIZE = DEFAULT_SEGMENT_SIZE * 2;
    public static final int MIN_SEGMENT_SIZE = 16 * 1024;       // not currently enforced in parsing due to existing payloads in testing
    public static final String KAS_PUBLIC_KEY_PATH = "/kas_public_key";
    public static final String DEFAULT_MIME_TYPE = "application/octet-stream";
    public static final int MAX_COLLECTION_ITERATION = (1 << 24) - 1;

    public enum TDFFormat {
        JSONFormat,
        XMLFormat
    }

    public enum IntegrityAlgorithm {
        HS256,
        GMAC
    }

    public static final int K_HTTP_OK = 200;

    public static class KASInfo implements Cloneable {
        public String URL;
        public String PublicKey;
        public String KID;
        public Boolean Default;
        public String Algorithm;

        @Override
        public KASInfo clone() {
            try {
                return (KASInfo) super.clone();
            } catch (CloneNotSupportedException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public String toString() {
            var sb = new StringBuilder("KASInfo{");
            if (this.URL != null) {
                sb.append("URL:\"").append(this.URL).append("\",");
            }
            if (this.PublicKey != null) {
                sb.append("PublicKey:\"").append(this.PublicKey).append("\",");
            }
            if (this.KID != null) {
                sb.append("KID:\"").append(this.KID).append("\",");
            }
            if (this.Default != null) {
                sb.append("Default:").append(this.Default).append(",");
            }
            if (this.Algorithm != null) {
                sb.append("Algorithm:\"").append(this.Algorithm).append("\",");
            }
            return sb.append("}").toString();
        }
    }

    public static class AssertionVerificationKeys {
        public AssertionConfig.AssertionKey defaultKey;
        public Map<String, AssertionConfig.AssertionKey> keys = new HashMap<>();

        Boolean isEmpty() {
            return this.defaultKey == null && this.keys.isEmpty();
        }

        AssertionConfig.AssertionKey getKey(String key) {
            var assertionKey = keys.get(key);
            if (assertionKey != null) {
                return assertionKey;
            }

            return defaultKey;
        }
    }

    public static class TDFReaderConfig {
        // Optional Map of Assertion Verification Keys
        AssertionVerificationKeys assertionVerificationKeys = new AssertionVerificationKeys();
        boolean disableAssertionVerification;
        KeyType sessionKeyType;
    }

    @SafeVarargs
    public static TDFReaderConfig newTDFReaderConfig(Consumer<TDFReaderConfig>... options) {
        TDFReaderConfig config = new TDFReaderConfig();
        config.disableAssertionVerification = false;
        config.sessionKeyType = KeyType.RSA2048Key;
        for (Consumer<TDFReaderConfig> option : options) {
            option.accept(config);
        }
        return config;
    }

    public static Consumer<TDFReaderConfig> withAssertionVerificationKeys(
            AssertionVerificationKeys assertionVerificationKeys) {
        return (TDFReaderConfig config) -> config.assertionVerificationKeys = assertionVerificationKeys;
    }

    public static Consumer<TDFReaderConfig> withDisableAssertionVerification(boolean disable) {
        return (TDFReaderConfig config) -> config.disableAssertionVerification = disable;
    }

    public static Consumer<TDFReaderConfig> WithSessionKeyType(KeyType keyType) {
        return (TDFReaderConfig config) -> config.sessionKeyType = keyType;
    }
    public static class TDFConfig {
        public Boolean autoconfigure;
        public int defaultSegmentSize;
        public boolean enableEncryption;
        public TDFFormat tdfFormat;
        public String tdfPublicKey;
        public String tdfPrivateKey;
        public String metaData;
        public IntegrityAlgorithm integrityAlgorithm;
        public IntegrityAlgorithm segmentIntegrityAlgorithm;
        public List<Autoconfigure.AttributeValueFQN> attributes;
        public List<Value> attributeValues;
        public List<KASInfo> kasInfoList;
        public List<io.opentdf.platform.sdk.AssertionConfig> assertionConfigList;
        public String mimeType;
        public List<Autoconfigure.KeySplitStep> splitPlan;
        public KeyType wrappingKeyType;
        public boolean hexEncodeRootAndSegmentHashes;
        public boolean renderVersionInfoInManifest;

        public TDFConfig() {
            this.autoconfigure = true;
            this.defaultSegmentSize = DEFAULT_SEGMENT_SIZE;
            this.enableEncryption = true;
            this.tdfFormat = TDFFormat.JSONFormat;
            this.integrityAlgorithm = IntegrityAlgorithm.HS256;
            this.segmentIntegrityAlgorithm = IntegrityAlgorithm.GMAC;
            this.attributes = new ArrayList<>();
            this.kasInfoList = new ArrayList<>();
            this.assertionConfigList = new ArrayList<>();
            this.mimeType = DEFAULT_MIME_TYPE;
            this.splitPlan = new ArrayList<>();
            this.wrappingKeyType = KeyType.RSA2048Key;
            this.hexEncodeRootAndSegmentHashes = false;
            this.renderVersionInfoInManifest = true;
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

    public static Consumer<TDFConfig> withDataAttributes(String... attributes) throws AutoConfigureException {
        List<Autoconfigure.AttributeValueFQN> attrValFqns = new ArrayList<Autoconfigure.AttributeValueFQN>();
        for (String a : attributes) {
            Autoconfigure.AttributeValueFQN attrValFqn = new Autoconfigure.AttributeValueFQN(a);
            attrValFqns.add(attrValFqn);
        }
        return (TDFConfig config) -> {
            config.attributeValues = null;
            config.attributes.addAll(attrValFqns);
        };
    }

    public static Consumer<TDFConfig> withDataAttributeValues(String... attributes) throws AutoConfigureException {
        List<Autoconfigure.AttributeValueFQN> attrValFqns = new ArrayList<Autoconfigure.AttributeValueFQN>();
        for (String a : attributes) {
            Autoconfigure.AttributeValueFQN attrValFqn = new Autoconfigure.AttributeValueFQN(a);
            attrValFqns.add(attrValFqn);
        }
        return (TDFConfig config) -> {
            config.attributeValues = null;
            config.attributes.addAll(attrValFqns);
        };
    }

    // WithDataAttributeValues appends the given data attributes to the bound
    // policy.
    // Unlike `WithDataAttributes`, this will not trigger an attribute definition
    // lookup
    // during autoconfigure. That is, to use autoconfigure in an 'offline' context,
    // you must first store the relevant attribute information locally and load
    // it to the `CreateTDF` method with this option.
    public static Consumer<TDFConfig> withDataAttributeValues(Value... attributes) throws AutoConfigureException {
        List<Autoconfigure.AttributeValueFQN> attrValFqns = new ArrayList<Autoconfigure.AttributeValueFQN>();
        List<Value> attrVals = new ArrayList<Value>();
        for (Value a : attributes) {
            attrVals.add(a);
            AttributeValueFQN afqn = new Autoconfigure.AttributeValueFQN(a.getFqn());
            attrValFqns.add(afqn);
        }
        return (TDFConfig config) -> {
            config.attributes.addAll(attrValFqns);
            config.attributeValues.addAll(attrVals);
        };
    }

    public static Consumer<TDFConfig> withKasInformation(KASInfo... kasInfoList) {
        return (TDFConfig config) -> {
            Collections.addAll(config.kasInfoList, kasInfoList);
        };
    }

    public static Consumer<TDFConfig> withSplitPlan(Autoconfigure.KeySplitStep... p) {
        return (TDFConfig config) -> {
            config.splitPlan = new ArrayList<>(Arrays.asList(p));
            config.autoconfigure = false;
        };
    }

    public static Consumer<TDFConfig> withAssertionConfig(io.opentdf.platform.sdk.AssertionConfig... assertionList) {
        return (TDFConfig config) -> {
            Collections.addAll(config.assertionConfigList, assertionList);
        };
    }

    public static Consumer<TDFConfig> withMetaData(String metaData) {
        return (TDFConfig config) -> config.metaData = metaData;
    }

    public static Consumer<TDFConfig> withSegmentSize(int size) {
        if (size > MAX_SEGMENT_SIZE) {
            throw new IllegalArgumentException("Segment size " + size + " exceeds the maximum " + MAX_SEGMENT_SIZE);
        } else if (size < MIN_SEGMENT_SIZE) {
            throw new IllegalArgumentException("Segment size " + size + " is under the minimum " + MIN_SEGMENT_SIZE);
        }

        return (TDFConfig config) -> config.defaultSegmentSize = size;
    }

    public static Consumer<TDFConfig> withAutoconfigure(boolean enable) {
        return (TDFConfig config) -> {
            config.autoconfigure = enable;
            config.splitPlan = null;
        };
    }

    // specify TDF version for TDF creation to target. Versions less than 4.3.0 will add a
    // layer of hex encoding to their segment hashes and will not include version information
    // in their manifests.
    public static Consumer<TDFConfig> withTargetMode(String targetVersion) {
        Version version = new Version(targetVersion == null ? "0.0.0" : targetVersion);
        return (TDFConfig config) -> {
            var legacyTDF = version.compareTo(new Version("4.3.0")) < 0;
            config.renderVersionInfoInManifest = !legacyTDF;
            config.hexEncodeRootAndSegmentHashes = legacyTDF;
        };
    }

    public static Consumer<TDFConfig> WithWrappingKeyAlg(KeyType    keyType) {
        return (TDFConfig config) -> config.wrappingKeyType = keyType;
    }

    // public static Consumer<TDFConfig> withDisableEncryption() {
    // return (TDFConfig config) -> config.enableEncryption = false;
    // }

    public static Consumer<TDFConfig> withMimeType(String mimeType) {
        return (TDFConfig config) -> config.mimeType = mimeType;
    }

    public static class NanoTDFConfig {
        public ECCMode eccMode;
        public NanoTDFType.Cipher cipher;
        public SymmetricAndPayloadConfig config;
        public List<String> attributes;
        public List<KASInfo> kasInfoList;
        public CollectionConfig collectionConfig;

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
            this.collectionConfig = new CollectionConfig(false);
        }
    }

    public static NanoTDFConfig newNanoTDFConfig(Consumer<NanoTDFConfig>... options) {
        NanoTDFConfig config = new NanoTDFConfig();
        for (Consumer<NanoTDFConfig> option : options) {
            option.accept(config);
        }
        return config;
    }

    public static Consumer<NanoTDFConfig> withCollection() {
        return (NanoTDFConfig config) -> {
            config.collectionConfig = new CollectionConfig(true);
        };
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
        return (NanoTDFConfig config) -> config.eccMode.setECDSABinding(true);
    }

    public static Consumer<NanoTDFConfig> WithECDSAPolicyBinding(boolean enable) {
        return (NanoTDFConfig config) -> config.eccMode.setECDSABinding(enable);
    }

    public static class HeaderInfo {
        private final Header header;
        private final AesGcm key;
        private final int iteration;

        public HeaderInfo(Header header,AesGcm key, int iteration) {
            this.header = header;
            this.key = key;
            this.iteration = iteration;
        }

        public Header getHeader() {
            return header;
        }

        public int getIteration() {
            return iteration;
        }

        public AesGcm getKey() {
            return key;
        }
    }

    public static class CollectionConfig {
        private int iterationCounter;
        private HeaderInfo headerInfo;
        public final boolean useCollection;
        private Boolean updatedHeaderInfo;


        public CollectionConfig(boolean useCollection) {
            this.useCollection = useCollection;
        }

        public synchronized HeaderInfo getHeaderInfo() throws InterruptedException {
            int iteration = iterationCounter;
            iterationCounter = (iterationCounter + 1) % MAX_COLLECTION_ITERATION;

            if (iteration == 0) {
                updatedHeaderInfo = false;
                return null;
            }
            while (!updatedHeaderInfo) {
                this.wait();
            }
            return new HeaderInfo(headerInfo.getHeader(), headerInfo.getKey(), iteration);
        }

        public synchronized void updateHeaderInfo(HeaderInfo headerInfo) {
            this.headerInfo = headerInfo;
            updatedHeaderInfo = true;
            this.notifyAll();
        }
    }
}
