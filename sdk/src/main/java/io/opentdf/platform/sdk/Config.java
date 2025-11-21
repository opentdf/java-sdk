package io.opentdf.platform.sdk;

import io.opentdf.platform.policy.KeyAccessServer;
import io.opentdf.platform.policy.SimpleKasKey;
import io.opentdf.platform.policy.Value;
import io.opentdf.platform.sdk.Autoconfigure.AttributeValueFQN;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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
    private static Logger logger = LoggerFactory.getLogger(Config.class);

    public enum TDFFormat {
        JSONFormat,
        XMLFormat
    }

    public enum IntegrityAlgorithm {
        HS256,
        GMAC
    }

    public static class KASInfo implements Cloneable {
        private String URL;
        private String PublicKey;
        private String KID;
        private Boolean Default;
        private String Algorithm;

        public KASInfo() {}

        public KASInfo(String URL, String publicKey, String KID, String algorithm) {
            this.URL = URL;
            PublicKey = publicKey;
            this.KID = KID;
            Algorithm = algorithm;
        }

        public String getURL() {
            return URL;
        }

        public void setURL(String URL) {
            this.URL = URL;
        }

        public String getPublicKey() {
            return PublicKey;
        }

        public void setPublicKey(String publicKey) {
            PublicKey = publicKey;
        }

        public String getKID() {
            return KID;
        }

        public void setKID(String KID) {
            this.KID = KID;
        }

        public Boolean getDefault() {
            return Default;
        }

        public void setDefault(Boolean aDefault) {
            Default = aDefault;
        }

        public String getAlgorithm() {
            return Algorithm;
        }

        public void setAlgorithm(String algorithm) {
            Algorithm = algorithm;
        }

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

        public static List<KASInfo> fromKeyAccessServer(KeyAccessServer kas) {
            var keys = kas.getPublicKey().getCached().getKeysList();
            if (keys.isEmpty()) {
                logger.warn("Invalid KAS key mapping for kas [{}]: publicKey is empty", kas.getUri());
                return Collections.emptyList();
            }
            return keys.stream().flatMap(ki -> {
                if (ki.getPem().isEmpty()) {
                    logger.warn("Invalid KAS key mapping for kas [{}]: publicKey PEM is empty", kas.getUri());
                    return Stream.empty();
                }
                Config.KASInfo kasInfo = new Config.KASInfo();
                kasInfo.URL = kas.getUri();
                kasInfo.KID = ki.getKid();
                kasInfo.Algorithm = KeyType.fromPublicKeyAlgorithm(ki.getAlg()).toString();
                kasInfo.PublicKey = ki.getPem();
                return Stream.of(kasInfo);
            }).collect(Collectors.toList());
        }

        public static KASInfo fromSimpleKasKey(SimpleKasKey ki) {
            Config.KASInfo kasInfo = new Config.KASInfo();
            kasInfo.URL = ki.getKasUri();
            kasInfo.KID = ki.getPublicKey().getKid();
            kasInfo.Algorithm = KeyType.fromAlgorithm(ki.getPublicKey().getAlgorithm()).toString();
            kasInfo.PublicKey = ki.getPublicKey().getPem();

            return kasInfo;
        }
    }

    public static class AssertionVerificationKeys {
        private AssertionConfig.AssertionKey defaultKey;
        private Map<String, AssertionConfig.AssertionKey> keys = new HashMap<>();

        public Map<String, AssertionConfig.AssertionKey> getKeys() {
            return keys;
        }

        public void setKeys(Map<String, AssertionConfig.AssertionKey> keys) {
            this.keys = keys;
        }

        public AssertionConfig.AssertionKey getDefaultKey() {
            return defaultKey;
        }

        public void setDefaultKey(AssertionConfig.AssertionKey defaultKey) {
            this.defaultKey = defaultKey;
        }

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
        private AssertionVerificationKeys assertionVerificationKeys = new AssertionVerificationKeys();
        private boolean disableAssertionVerification;
        private KeyType sessionKeyType;
        private Set<String> kasAllowlist;
        private boolean ignoreKasAllowlist;

        public void setAssertionVerificationKeys(AssertionVerificationKeys assertionVerificationKeys) {
            this.assertionVerificationKeys = assertionVerificationKeys;
        }

        public void setDisableAssertionVerification(boolean disableAssertionVerification) {
            this.disableAssertionVerification = disableAssertionVerification;
        }

        public void setSessionKeyType(KeyType sessionKeyType) {
            this.sessionKeyType = sessionKeyType;
        }

        public void setKasAllowlist(Set<String> kasAllowlist) {
            this.kasAllowlist = kasAllowlist;
        }

        public void setIgnoreKasAllowlist(boolean ignoreKasAllowlist) {
            this.ignoreKasAllowlist = ignoreKasAllowlist;
        }

        public AssertionVerificationKeys getAssertionVerificationKeys() {
            return assertionVerificationKeys;
        }

        public boolean isDisableAssertionVerification() {
            return disableAssertionVerification;
        }

        public KeyType getSessionKeyType() {
            return sessionKeyType;
        }

        public Set<String> getKasAllowlist() {
            return kasAllowlist;
        }

        public boolean isIgnoreKasAllowlist() {
            return ignoreKasAllowlist;
        }
    }

    @SafeVarargs
    public static TDFReaderConfig newTDFReaderConfig(Consumer<TDFReaderConfig>... options) {
        TDFReaderConfig config = new TDFReaderConfig();
        config.disableAssertionVerification = false;
        config.sessionKeyType = KeyType.RSA2048Key;
        config.kasAllowlist = new HashSet<>();
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
    public static Consumer<TDFReaderConfig> WithKasAllowlist(String... kasAllowlist) {
        return (TDFReaderConfig config) -> config.kasAllowlist = Arrays
                .stream(kasAllowlist)
                .map(Config::getKasAddress).collect(Collectors.toSet());
    }

    public static Consumer<TDFReaderConfig> withKasAllowlist(Set<String> kasAllowlist) {
        return (TDFReaderConfig config) -> {
            config.kasAllowlist = kasAllowlist;
        };
    }

    public static Consumer<TDFReaderConfig> WithIgnoreKasAllowlist(boolean ignore) {
        return (TDFReaderConfig config) -> config.ignoreKasAllowlist = ignore;
    }


    public static class TDFConfig {
        private Boolean autoconfigure;
        private int defaultSegmentSize;
        private boolean enableEncryption;
        private TDFFormat tdfFormat;
        private String tdfPublicKey;
        private String tdfPrivateKey;
        private String metaData;
        private IntegrityAlgorithm integrityAlgorithm;
        private IntegrityAlgorithm segmentIntegrityAlgorithm;
        private List<Autoconfigure.AttributeValueFQN> attributes;
        private List<Value> attributeValues;
        private List<KASInfo> kasInfoList;
        private List<io.opentdf.platform.sdk.AssertionConfig> assertionConfigList;
        private String mimeType;
        private List<Autoconfigure.KeySplitStep> splitPlan;
        private KeyType wrappingKeyType;
        private boolean hexEncodeRootAndSegmentHashes;
        private boolean renderVersionInfoInManifest;
        private boolean systemMetadataAssertion;

        public Boolean getAutoconfigure() {
            return autoconfigure;
        }

        public void setAutoconfigure(Boolean autoconfigure) {
            this.autoconfigure = autoconfigure;
        }

        public int getDefaultSegmentSize() {
            return defaultSegmentSize;
        }

        public void setDefaultSegmentSize(int defaultSegmentSize) {
            this.defaultSegmentSize = defaultSegmentSize;
        }

        public boolean isEnableEncryption() {
            return enableEncryption;
        }

        public void setEnableEncryption(boolean enableEncryption) {
            this.enableEncryption = enableEncryption;
        }

        public TDFFormat getTdfFormat() {
            return tdfFormat;
        }

        public void setTdfFormat(TDFFormat tdfFormat) {
            this.tdfFormat = tdfFormat;
        }

        public String getTdfPublicKey() {
            return tdfPublicKey;
        }

        public void setTdfPublicKey(String tdfPublicKey) {
            this.tdfPublicKey = tdfPublicKey;
        }

        public String getTdfPrivateKey() {
            return tdfPrivateKey;
        }

        public void setTdfPrivateKey(String tdfPrivateKey) {
            this.tdfPrivateKey = tdfPrivateKey;
        }

        public String getMetaData() {
            return metaData;
        }

        public void setMetaData(String metaData) {
            this.metaData = metaData;
        }

        public IntegrityAlgorithm getIntegrityAlgorithm() {
            return integrityAlgorithm;
        }

        public void setIntegrityAlgorithm(IntegrityAlgorithm integrityAlgorithm) {
            this.integrityAlgorithm = integrityAlgorithm;
        }

        public IntegrityAlgorithm getSegmentIntegrityAlgorithm() {
            return segmentIntegrityAlgorithm;
        }

        public void setSegmentIntegrityAlgorithm(IntegrityAlgorithm segmentIntegrityAlgorithm) {
            this.segmentIntegrityAlgorithm = segmentIntegrityAlgorithm;
        }

        public List<AttributeValueFQN> getAttributes() {
            return attributes;
        }

        public void setAttributes(List<AttributeValueFQN> attributes) {
            this.attributes = attributes;
        }

        public List<Value> getAttributeValues() {
            return attributeValues;
        }

        public void setAttributeValues(List<Value> attributeValues) {
            this.attributeValues = attributeValues;
        }

        public List<KASInfo> getKasInfoList() {
            return kasInfoList;
        }

        public void setKasInfoList(List<KASInfo> kasInfoList) {
            this.kasInfoList = kasInfoList;
        }

        public List<AssertionConfig> getAssertionConfigList() {
            return assertionConfigList;
        }

        public void setAssertionConfigList(List<AssertionConfig> assertionConfigList) {
            this.assertionConfigList = assertionConfigList;
        }

        public String getMimeType() {
            return mimeType;
        }

        public void setMimeType(String mimeType) {
            this.mimeType = mimeType;
        }

        public List<Autoconfigure.KeySplitStep> getSplitPlan() {
            return splitPlan;
        }

        public void setSplitPlan(List<Autoconfigure.KeySplitStep> splitPlan) {
            this.splitPlan = splitPlan;
        }

        public KeyType getWrappingKeyType() {
            return wrappingKeyType;
        }

        public void setWrappingKeyType(KeyType wrappingKeyType) {
            this.wrappingKeyType = wrappingKeyType;
        }

        public boolean isHexEncodeRootAndSegmentHashes() {
            return hexEncodeRootAndSegmentHashes;
        }

        public void setHexEncodeRootAndSegmentHashes(boolean hexEncodeRootAndSegmentHashes) {
            this.hexEncodeRootAndSegmentHashes = hexEncodeRootAndSegmentHashes;
        }

        public boolean getRenderVersionInfoInManifest() {
            return renderVersionInfoInManifest;
        }

        public void setRenderVersionInfoInManifest(boolean renderVersionInfoInManifest) {
            this.renderVersionInfoInManifest = renderVersionInfoInManifest;
        }

        public boolean isSystemMetadataAssertion() {
            return systemMetadataAssertion;
        }

        public void setSystemMetadataAssertion(boolean systemMetadataAssertion) {
            this.systemMetadataAssertion = systemMetadataAssertion;
        }

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
            this.systemMetadataAssertion = false;
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

    /**
     * Deprecated since 9.1.0, will be removed. To produce key shares use
     * the key mapping feature
     */
    @Deprecated(since = "9.1.0", forRemoval = true)
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

    public static Consumer<TDFConfig> withSystemMetadataAssertion() {
        return (TDFConfig config) -> config.systemMetadataAssertion = true;
    }

    public static class NanoTDFConfig {
        private ECCMode eccMode;
        private NanoTDFType.Cipher cipher;
        private SymmetricAndPayloadConfig config;
        private List<String> attributes;
        private List<KASInfo> kasInfoList;
        private CollectionConfig collectionConfig;
        private NanoTDFType.PolicyType policyType;

        public ECCMode getEccMode() {
            return eccMode;
        }

        public NanoTDFType.Cipher getCipher() {
            return cipher;
        }

        public SymmetricAndPayloadConfig getConfig() {
            return config;
        }

        public List<String> getAttributes() {
            return attributes;
        }

        public List<KASInfo> getKasInfoList() {
            return kasInfoList;
        }

        public CollectionConfig getCollectionConfig() {
            return collectionConfig;
        }

        public NanoTDFType.PolicyType getPolicyType() {
            return policyType;
        }



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
            this.policyType = NanoTDFType.PolicyType.EMBEDDED_POLICY_ENCRYPTED;
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

    public static Consumer<NanoTDFConfig> withPolicyType(NanoTDFType.PolicyType policyType) {
        return (NanoTDFConfig config) -> config.policyType = policyType;
    }

    public static class NanoTDFReaderConfig {
        private Set<String> kasAllowlist;
        private boolean ignoreKasAllowlist;

        public void setKasAllowlist(Set<String> kasAllowlist) {
            this.kasAllowlist = kasAllowlist;
        }

        public void setIgnoreKasAllowlist(boolean ignoreKasAllowlist) {
            this.ignoreKasAllowlist = ignoreKasAllowlist;
        }

        public Set<String> getKasAllowlist() {
            return kasAllowlist;
        }

        public boolean isIgnoreKasAllowlist() {
            return ignoreKasAllowlist;
        }
    }

    public static NanoTDFReaderConfig newNanoTDFReaderConfig(Consumer<NanoTDFReaderConfig>... options) {
        NanoTDFReaderConfig config = new NanoTDFReaderConfig();
        for (Consumer<NanoTDFReaderConfig> option : options) {
            option.accept(config);
        }
        return config;
    }

    public static Consumer<NanoTDFReaderConfig> WithNanoKasAllowlist(String... kasAllowlist) {
        return (NanoTDFReaderConfig config) -> {
            // apply getKasAddress to each kasAllowlist entry and add to hashset
            config.kasAllowlist = Arrays.stream(kasAllowlist)
                    .map(Config::getKasAddress)
                    .collect(Collectors.toSet());
        };
    }

    public static Consumer<NanoTDFReaderConfig> withNanoKasAllowlist(Set<String> kasAllowlist) {
        return (NanoTDFReaderConfig config) -> {
            config.kasAllowlist = kasAllowlist;
        };
    }

    public static Consumer<NanoTDFReaderConfig> WithNanoIgnoreKasAllowlist(boolean ignore) {
        return (NanoTDFReaderConfig config) -> config.ignoreKasAllowlist = ignore;
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
        private final boolean useCollection;
        private Boolean updatedHeaderInfo;

        public boolean getUseCollection() {
            return useCollection;
        }


        public CollectionConfig(boolean useCollection) {
            this.useCollection = useCollection;
        }

        public synchronized HeaderInfo getHeaderInfo() throws SDKException {
            int iteration = iterationCounter;
            iterationCounter = (iterationCounter + 1) % MAX_COLLECTION_ITERATION;

            if (iteration == 0) {
                updatedHeaderInfo = false;
                return null;
            }
            while (!updatedHeaderInfo) {
                try {
                    this.wait();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new SDKException("interrupted while waiting for header info", e);
                }
            }
            return new HeaderInfo(headerInfo.getHeader(), headerInfo.getKey(), iteration);
        }

        public synchronized void updateHeaderInfo(HeaderInfo headerInfo) {
            this.headerInfo = headerInfo;
            updatedHeaderInfo = true;
            this.notifyAll();
        }
    }

    public static String getKasAddress(String kasURL) throws SDKException {
        // Prepend "https://" if no scheme is provided
        if (!kasURL.contains("://")) {
            kasURL = "https://" + kasURL;
        }

        URI uri;
        try {
            uri = new URI(kasURL);
        } catch (URISyntaxException e) {
            throw new SDKException("error constructing KAS url", e);
        }

        // Default to "https" if no scheme is provided
        String scheme = uri.getScheme();
        if (scheme == null) {
            scheme = "https";
        }

        // Default to port 443 if no port is provided
        int port = uri.getPort();
        if (port == -1) {
            port = 443;
        }

        // Reconstruct the URL with only the scheme, host, and port
        try {
            return new URI(scheme, null, uri.getHost(), port, null, null, null).toString();
        } catch (URISyntaxException e) {
            throw new SDKException("error creating KAS URL from host and port", e);
        }
    }
}
