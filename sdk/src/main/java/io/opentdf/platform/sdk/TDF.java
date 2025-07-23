package io.opentdf.platform.sdk;

import com.connectrpc.ConnectException;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.nimbusds.jose.*;

import io.opentdf.platform.policy.Value;
import io.opentdf.platform.policy.kasregistry.ListKeyAccessServersRequest;
import io.opentdf.platform.policy.kasregistry.ListKeyAccessServersResponse;
import io.opentdf.platform.sdk.Config.TDFConfig;
import io.opentdf.platform.sdk.Autoconfigure.AttributeValueFQN;
import io.opentdf.platform.sdk.Config.KASInfo;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.text.ParseException;
import java.util.*;

/**
 * The TDF class is responsible for handling operations related to
 * Trusted Data Format (TDF). It includes methods to create and load
 * TDF objects, as well as utility functions to handle cryptographic
 * operations and configurations.
 */
class TDF {

    private static byte[] tdfECKeySaltCompute() {
        byte[] salt;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update("TDF".getBytes());
            salt = digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("failed to compute salt for TDF", e);
        }
        return salt;
    }

    public static final byte[] GLOBAL_KEY_SALT = tdfECKeySaltCompute();
    static final String EMPTY_SPLIT_ID = ""; // Made package-private for TDFTest usage if needed, or could be private if
                                             // not used by TDFTest
    /**
     * The TDF specification version this SDK implements.
     */
    public static final String TDF_SPEC_VERSION = "4.3.0";
    private static final String KEY_ACCESS_SCHEMA_VERSION = "1.0";
    private final long maximumSize;

    private final SDK.Services services;

    /**
     * Constructs a new TDF instance using the default maximum input size defined by
     * MAX_TDF_INPUT_SIZE.
     * <p>
     * This constructor is primarily used to initialize the TDF object with the
     * standard maximum
     * input size, which controls the maximum size of the input data that can be
     * processed.
     * For test purposes, an alternative constructor allows for setting a custom
     * maximum input size.
     */
    TDF(SDK.Services services) {
        this(MAX_TDF_INPUT_SIZE, services);
    }

    // constructor for tests so that we can set a maximum size that's tractable for
    // tests
    TDF(long maximumInputSize, SDK.Services services) {
        this.maximumSize = maximumInputSize;
        this.services = services;
    }

    private static final Logger logger = LoggerFactory.getLogger(TDF.class);

    private static final long MAX_TDF_INPUT_SIZE = 68719476736L;
    private static final int GCM_KEY_SIZE = 32;
    private static final String kSplitKeyType = "split";
    private static final String kWrapped = "wrapped";
    private static final String kECWrapped = "ec-wrapped";
    private static final String kKasProtocol = "kas";
    private static final int kGcmIvSize = 12;
    private static final int kAesBlockSize = 16;
    private static final String kGCMCipherAlgorithm = "AES-256-GCM";
    private static final int kGMACPayloadLength = 16;
    private static final String kGmacIntegrityAlgorithm = "GMAC";

    private static final String kHmacIntegrityAlgorithm = "HS256";
    private static final String kTDFAsZip = "zip";
    private static final String kTDFZipReference = "reference";

    private static final SecureRandom sRandom = new SecureRandom();

    private static final Gson gson = new GsonBuilder().create();

    static class EncryptedMetadata {
        private String ciphertext;
        private String iv;
    }

    static class ECKeyWrappedKeyInfo {
        private String publicKey;
        private String wrappedKey;
    }

    static class TDFObject {
        public Manifest getManifest() {
            return manifest;
        }

        private Manifest manifest;
        private long size;
        private AesGcm aesGcm;
        private final byte[] payloadKey = new byte[GCM_KEY_SIZE];

        public TDFObject() {
            this.manifest = new Manifest();
            this.manifest.encryptionInformation = new Manifest.EncryptionInformation();
            this.manifest.encryptionInformation.integrityInformation = new Manifest.IntegrityInformation();
            this.manifest.encryptionInformation.method = new Manifest.Method();
            this.size = 0;
        }

        private PolicyObject createPolicyObject(List<Autoconfigure.AttributeValueFQN> attributes) {
            PolicyObject policyObject = new PolicyObject();
            policyObject.body = new PolicyObject.Body();
            policyObject.uuid = UUID.randomUUID().toString();
            policyObject.body.dataAttributes = new ArrayList<>(attributes.size());
            policyObject.body.dissem = new ArrayList<>();

            for (Autoconfigure.AttributeValueFQN attribute : attributes) {
                PolicyObject.AttributeObject attributeObject = new PolicyObject.AttributeObject();
                attributeObject.attribute = attribute.toString();
                policyObject.body.dataAttributes.add(attributeObject);
            }
            return policyObject;
        }

        private static final Base64.Encoder encoder = Base64.getEncoder();

        private void prepareManifest(Config.TDFConfig tdfConfig, SDK.KAS kas) {
            manifest.tdfVersion = tdfConfig.renderVersionInfoInManifest ? TDF_SPEC_VERSION : null;
            manifest.encryptionInformation.keyAccessType = kSplitKeyType;
            manifest.encryptionInformation.keyAccessObj = new ArrayList<>();

            PolicyObject policyObject = createPolicyObject(tdfConfig.attributes);
            String base64PolicyObject = encoder
                    .encodeToString(gson.toJson(policyObject).getBytes(StandardCharsets.UTF_8));
            Map<String, Config.KASInfo> latestKASInfo = new HashMap<>();
            if (tdfConfig.splitPlan == null || tdfConfig.splitPlan.isEmpty()) {
                // Default split plan: Split keys across all KASes
                List<Autoconfigure.KeySplitStep> splitPlan = new ArrayList<>(tdfConfig.kasInfoList.size());
                int i = 0;
                for (Config.KASInfo kasInfo : tdfConfig.kasInfoList) {
                    Autoconfigure.KeySplitStep step = new Autoconfigure.KeySplitStep(kasInfo.URL, "");
                    if (tdfConfig.kasInfoList.size() > 1) {
                        step.splitID = String.format("s-%d", i++);
                    }
                    splitPlan.add(step);
                    if (kasInfo.PublicKey != null && !kasInfo.PublicKey.isEmpty()) {
                        latestKASInfo.put(kasInfo.URL, kasInfo);
                    }
                }
                tdfConfig.splitPlan = splitPlan;
            }

            // Seed anything passed in manually
            for (Config.KASInfo kasInfo : tdfConfig.kasInfoList) {
                if (kasInfo.PublicKey != null && !kasInfo.PublicKey.isEmpty()) {
                    latestKASInfo.put(kasInfo.URL, kasInfo);
                }
            }

            // split plan: restructure by conjunctions
            Map<String, List<Config.KASInfo>> conjunction = new HashMap<>();
            List<String> splitIDs = new ArrayList<>();

            for (Autoconfigure.KeySplitStep splitInfo : tdfConfig.splitPlan) {
                // Public key was passed in with kasInfoList
                // TODO First look up in attribute information / add to split plan?
                Config.KASInfo ki = latestKASInfo.get(splitInfo.kas);
                if (ki == null || ki.PublicKey == null || ki.PublicKey.isBlank()) {
                    logger.info("no public key provided for KAS at {}, retrieving", splitInfo.kas);
                    var getKI = new Config.KASInfo();
                    getKI.URL = splitInfo.kas;
                    getKI.Algorithm = tdfConfig.wrappingKeyType.toString();
                    getKI = kas.getPublicKey(getKI);
                    latestKASInfo.put(splitInfo.kas, getKI);
                    ki = getKI;
                }
                if (conjunction.containsKey(splitInfo.splitID)) {
                    conjunction.get(splitInfo.splitID).add(ki);
                } else {
                    List<Config.KASInfo> newList = new ArrayList<>();
                    newList.add(ki);
                    conjunction.put(splitInfo.splitID, newList);
                    splitIDs.add(splitInfo.splitID);
                }
            }

            List<byte[]> symKeys = new ArrayList<>(splitIDs.size());
            for (String splitID : splitIDs) {
                // Symmetric key
                byte[] symKey = new byte[GCM_KEY_SIZE];
                sRandom.nextBytes(symKey);
                symKeys.add(symKey);

                // Add policyBinding
                var hexBinding = Hex.encodeHexString(
                        CryptoUtils.CalculateSHA256Hmac(symKey, base64PolicyObject.getBytes(StandardCharsets.UTF_8)));
                var policyBinding = new Manifest.PolicyBinding();
                policyBinding.alg = kHmacIntegrityAlgorithm;
                policyBinding.hash = encoder.encodeToString(hexBinding.getBytes(StandardCharsets.UTF_8));

                // Add meta data
                var encryptedMetadata = "";
                if (tdfConfig.metaData != null && !tdfConfig.metaData.trim().isEmpty()) {
                    AesGcm aesGcm = new AesGcm(symKey);
                    var encrypted = aesGcm.encrypt(tdfConfig.metaData.getBytes(StandardCharsets.UTF_8));

                    EncryptedMetadata em = new EncryptedMetadata();
                    em.iv = encoder.encodeToString(encrypted.getIv());
                    em.ciphertext = encoder.encodeToString(encrypted.asBytes());

                    var metadata = gson.toJson(em);
                    encryptedMetadata = encoder.encodeToString(metadata.getBytes(StandardCharsets.UTF_8));
                }

                for (Config.KASInfo kasInfo : conjunction.get(splitID)) {
                    if (kasInfo.PublicKey == null || kasInfo.PublicKey.isEmpty()) {
                        throw new SDK.KasPublicKeyMissing("Kas public key is missing in kas information list");
                    }

                    var keyAccess = createKeyAccess(tdfConfig, kasInfo, symKey, policyBinding, encryptedMetadata,
                            splitID);
                    manifest.encryptionInformation.keyAccessObj.add(keyAccess);
                }
            }

            manifest.encryptionInformation.policy = base64PolicyObject;
            manifest.encryptionInformation.method.algorithm = kGCMCipherAlgorithm;

            // Create the payload key by XOR all the keys in key access object.
            for (byte[] symKey : symKeys) {
                for (int index = 0; index < symKey.length; index++) {
                    this.payloadKey[index] ^= symKey[index];
                }
            }

            this.aesGcm = new AesGcm(this.payloadKey);
        }

        private Manifest.KeyAccess createKeyAccess(Config.TDFConfig tdfConfig, Config.KASInfo kasInfo, byte[] symKey,
                Manifest.PolicyBinding policyBinding, String encryptedMetadata, String splitID) {
            Manifest.KeyAccess keyAccess = new Manifest.KeyAccess();
            keyAccess.keyType = kWrapped;
            keyAccess.url = kasInfo.URL;
            keyAccess.kid = kasInfo.KID;
            keyAccess.protocol = kKasProtocol;
            keyAccess.policyBinding = policyBinding;
            keyAccess.encryptedMetadata = encryptedMetadata;
            keyAccess.sid = splitID;
            keyAccess.schemaVersion = KEY_ACCESS_SCHEMA_VERSION;

            if (tdfConfig.wrappingKeyType.isEc()) {
                var ecKeyWrappedKeyInfo = createECWrappedKey(tdfConfig, kasInfo, symKey);
                keyAccess.wrappedKey = ecKeyWrappedKeyInfo.wrappedKey;
                keyAccess.ephemeralPublicKey = ecKeyWrappedKeyInfo.publicKey;
                keyAccess.keyType = kECWrapped;
            } else {
                keyAccess.wrappedKey = createRSAWrappedKey(kasInfo, symKey);
                keyAccess.keyType = kWrapped;
            }
            return keyAccess;
        }

        private ECKeyWrappedKeyInfo createECWrappedKey(Config.TDFConfig tdfConfig, Config.KASInfo kasInfo,
                byte[] symKey) {
            var curveName = tdfConfig.wrappingKeyType.getECCurve();
            var keyPair = new ECKeyPair(curveName, ECKeyPair.ECAlgorithm.ECDH);

            ECPublicKey kasPubKey = ECKeyPair.publicKeyFromPem(kasInfo.PublicKey);
            byte[] symmetricKey = ECKeyPair.computeECDHKey(kasPubKey, keyPair.getPrivateKey());

            var sessionKey = ECKeyPair.calculateHKDF(GLOBAL_KEY_SALT, symmetricKey);

            AesGcm gcm = new AesGcm(sessionKey);
            AesGcm.Encrypted wrappedKey = gcm.encrypt(symKey);

            ECKeyWrappedKeyInfo wrappedKeyInfo = new ECKeyWrappedKeyInfo();
            wrappedKeyInfo.publicKey = keyPair.publicKeyInPEMFormat();
            wrappedKeyInfo.wrappedKey = Base64.getEncoder().encodeToString(wrappedKey.asBytes());
            return wrappedKeyInfo;
        }

        private String createRSAWrappedKey(Config.KASInfo kasInfo, byte[] symKey) {
            AsymEncryption asymEncrypt = new AsymEncryption(kasInfo.PublicKey);
            byte[] wrappedKey = asymEncrypt.encrypt(symKey);
            return Base64.getEncoder().encodeToString(wrappedKey);
        }
    }

    private static final Base64.Decoder decoder = Base64.getDecoder();

    public static class Reader {
        private final TDFReader tdfReader;
        private final byte[] payloadKey;
        private final Manifest manifest;

        public String getMetadata() {
            return unencryptedMetadata;
        }

        public Manifest getManifest() {
            return manifest;
        }

        private final String unencryptedMetadata;
        private final AesGcm aesGcm;

        Reader(TDFReader tdfReader, Manifest manifest, byte[] payloadKey, String unencryptedMetadata) {
            this.tdfReader = tdfReader;
            this.manifest = manifest;
            this.aesGcm = new AesGcm(payloadKey);
            this.payloadKey = payloadKey;
            this.unencryptedMetadata = unencryptedMetadata;

        }

        public void readPayload(OutputStream outputStream) throws SDK.SegmentSignatureMismatch, IOException {

            MessageDigest digest = null;
            try {
                digest = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("error getting instance of SHA-256", e);
            }

            for (Manifest.Segment segment : manifest.encryptionInformation.integrityInformation.segments) {
                if (segment.encryptedSegmentSize > Config.MAX_SEGMENT_SIZE) {
                    throw new IllegalStateException("Segment size " + segment.encryptedSegmentSize + " exceeded limit "
                            + Config.MAX_SEGMENT_SIZE);
                } // MIN_SEGMENT_SIZE NOT validated out due to tests needing small segment sizes
                  // with existing payloads

                byte[] readBuf = new byte[(int) segment.encryptedSegmentSize];
                int bytesRead = tdfReader.readPayloadBytes(readBuf);

                if (readBuf.length != bytesRead) {
                    throw new IllegalStateException("unable to read bytes for segment (wanted "
                            + segment.encryptedSegmentSize + " but got " + bytesRead + ")");
                }

                var isLegacyTdf = manifest.tdfVersion == null || manifest.tdfVersion.isEmpty();

                if (manifest.payload.isEncrypted) {
                    String segHashAlg = manifest.encryptionInformation.integrityInformation.segmentHashAlg;
                    Config.IntegrityAlgorithm sigAlg = Config.IntegrityAlgorithm.HS256;
                    if (segHashAlg.compareToIgnoreCase(kGmacIntegrityAlgorithm) == 0) {
                        sigAlg = Config.IntegrityAlgorithm.GMAC;
                    }

                    var payloadSig = calculateSignature(readBuf, payloadKey, sigAlg);
                    if (isLegacyTdf) {
                        payloadSig = Hex.encodeHexString(payloadSig).getBytes(StandardCharsets.UTF_8);
                    }

                    if (segment.hash.compareTo(Base64.getEncoder().encodeToString(payloadSig)) != 0) {
                        throw new SDK.SegmentSignatureMismatch("segment signature miss match");
                    }

                    byte[] writeBuf = aesGcm.decrypt(new AesGcm.Encrypted(readBuf));
                    outputStream.write(writeBuf);

                } else {
                    String segmentSig = Hex.encodeHexString(digest.digest(readBuf));
                    if (segment.hash.compareTo(segmentSig) != 0) {
                        throw new SDK.SegmentSignatureMismatch("segment signature miss match");
                    }

                    outputStream.write(readBuf);
                }
            }
        }

        public PolicyObject readPolicyObject() {
            return tdfReader.readPolicyObject();
        }
    }

    private static byte[] calculateSignature(byte[] data, byte[] secret, Config.IntegrityAlgorithm algorithm) {
        if (algorithm == Config.IntegrityAlgorithm.HS256) {
            return CryptoUtils.CalculateSHA256Hmac(secret, data);
        }

        if (kGMACPayloadLength > data.length) {
            throw new IllegalArgumentException("tried to calculate GMAC on too small a payload. payload is "
                    + data.length + "bytes while GMAC is " + kGMACPayloadLength + " bytes");
        }

        return Arrays.copyOfRange(data, data.length - kGMACPayloadLength, data.length);
    }

    TDFObject createTDF(InputStream payload, OutputStream outputStream, Config.TDFConfig tdfConfig)
            throws SDKException, IOException {

        if (tdfConfig.autoconfigure) {
            Autoconfigure.Granter granter = new Autoconfigure.Granter(new ArrayList<>());
            if (tdfConfig.attributeValues != null && !tdfConfig.attributeValues.isEmpty()) {
                granter = Autoconfigure.newGranterFromAttributes(tdfConfig.attributeValues.toArray(new Value[0]));
            } else if (tdfConfig.attributes != null && !tdfConfig.attributes.isEmpty()) {
                granter = Autoconfigure.newGranterFromService(services.attributes(), services.kas().getKeyCache(),
                        tdfConfig.attributes.toArray(new AttributeValueFQN[0]));
            }

            if (granter == null) {
                throw new AutoConfigureException("Failed to create Granter"); // Replace with appropriate error handling
            }

            List<String> dk = defaultKases(tdfConfig);
            tdfConfig.splitPlan = granter.plan(dk, () -> UUID.randomUUID().toString());

            if (tdfConfig.splitPlan == null) {
                throw new AutoConfigureException("Failed to generate Split Plan"); // Replace with appropriate error
                // handling
            }
        }

        if (tdfConfig.kasInfoList.isEmpty() && (tdfConfig.splitPlan == null || tdfConfig.splitPlan.isEmpty())) {
            throw new SDK.KasInfoMissing("kas information is missing, no key access template specified or inferred");
        }

        // Add System Metadata Assertion if configured
        if (tdfConfig.systemMetadataAssertion) {
            AssertionConfig systemAssertion = AssertionConfig.getSystemMetadataAssertionConfig(TDF_SPEC_VERSION);
            tdfConfig.assertionConfigList.add(systemAssertion);
        }

        TDFObject tdfObject = new TDFObject();
        tdfObject.prepareManifest(tdfConfig, services.kas());

        long encryptedSegmentSize = tdfConfig.defaultSegmentSize + kGcmIvSize + kAesBlockSize;
        TDFWriter tdfWriter = new TDFWriter(outputStream);

        ByteArrayOutputStream aggregateHash = new ByteArrayOutputStream();
        byte[] readBuf = new byte[tdfConfig.defaultSegmentSize];

        tdfObject.manifest.encryptionInformation.integrityInformation.segments = new ArrayList<>();
        long totalSize = 0;
        boolean finished;
        try (var payloadOutput = tdfWriter.payload()) {
            do {
                int nRead = 0;
                int readThisLoop = 0;
                while (readThisLoop < readBuf.length
                        && (nRead = payload.read(readBuf, readThisLoop, readBuf.length - readThisLoop)) > 0) {
                    readThisLoop += nRead;
                }
                finished = nRead < 0;
                totalSize += readThisLoop;

                if (totalSize > maximumSize) {
                    throw new SDK.DataSizeNotSupported("can't create tdf larger than 64gb");
                }

                byte[] cipherData;
                byte[] segmentSig;
                Manifest.Segment segmentInfo = new Manifest.Segment();

                // encrypt
                cipherData = tdfObject.aesGcm.encrypt(readBuf, 0, readThisLoop).asBytes();
                payloadOutput.write(cipherData);

                segmentSig = calculateSignature(cipherData, tdfObject.payloadKey, tdfConfig.segmentIntegrityAlgorithm);
                if (tdfConfig.hexEncodeRootAndSegmentHashes) {
                    segmentSig = Hex.encodeHexString(segmentSig).getBytes(StandardCharsets.UTF_8);
                }
                segmentInfo.hash = Base64.getEncoder().encodeToString(segmentSig);

                aggregateHash.write(segmentSig);
                segmentInfo.segmentSize = readThisLoop;
                segmentInfo.encryptedSegmentSize = cipherData.length;

                tdfObject.manifest.encryptionInformation.integrityInformation.segments.add(segmentInfo);
            } while (!finished);
        }

        Manifest.RootSignature rootSignature = new Manifest.RootSignature();

        byte[] rootSig = calculateSignature(aggregateHash.toByteArray(), tdfObject.payloadKey,
                tdfConfig.integrityAlgorithm);
        byte[] encodedRootSig = tdfConfig.hexEncodeRootAndSegmentHashes
                ? Hex.encodeHexString(rootSig).getBytes(StandardCharsets.UTF_8)
                : rootSig;
        rootSignature.signature = Base64.getEncoder().encodeToString(encodedRootSig);

        String alg = kGmacIntegrityAlgorithm;
        if (tdfConfig.integrityAlgorithm == Config.IntegrityAlgorithm.HS256) {
            alg = kHmacIntegrityAlgorithm;
        }
        rootSignature.algorithm = alg;

        tdfObject.manifest.encryptionInformation.integrityInformation.rootSignature = rootSignature;
        tdfObject.manifest.encryptionInformation.integrityInformation.segmentSizeDefault = tdfConfig.defaultSegmentSize;
        tdfObject.manifest.encryptionInformation.integrityInformation.encryptedSegmentSizeDefault = (int) encryptedSegmentSize;

        tdfObject.manifest.encryptionInformation.integrityInformation.segmentHashAlg = kGmacIntegrityAlgorithm;
        if (tdfConfig.segmentIntegrityAlgorithm == Config.IntegrityAlgorithm.HS256) {
            tdfObject.manifest.encryptionInformation.integrityInformation.segmentHashAlg = kHmacIntegrityAlgorithm;
        }

        tdfObject.manifest.encryptionInformation.method.IsStreamable = true;

        // Add payload info
        tdfObject.manifest.payload = new Manifest.Payload();
        tdfObject.manifest.payload.mimeType = tdfConfig.mimeType;
        tdfObject.manifest.payload.protocol = kTDFAsZip;
        tdfObject.manifest.payload.type = kTDFZipReference;
        tdfObject.manifest.payload.url = TDFWriter.TDF_PAYLOAD_FILE_NAME;
        tdfObject.manifest.payload.isEncrypted = true;

        List<Manifest.Assertion> signedAssertions = new ArrayList<>(tdfConfig.assertionConfigList.size());

        for (var assertionConfig : tdfConfig.assertionConfigList) {
            var assertion = new Manifest.Assertion();
            assertion.id = assertionConfig.id;
            assertion.type = assertionConfig.type.toString();
            assertion.scope = assertionConfig.scope.toString();
            assertion.statement = assertionConfig.statement;
            assertion.appliesToState = assertionConfig.appliesToState.toString();

            var assertionHashAsHex = assertion.hash();
            byte[] assertionHash;
            if (tdfConfig.hexEncodeRootAndSegmentHashes) {
                assertionHash = assertionHashAsHex.getBytes(StandardCharsets.UTF_8);
            } else {
                try {
                    assertionHash = Hex.decodeHex(assertionHashAsHex);
                } catch (DecoderException e) {
                    throw new SDKException("error decoding assertion hash", e);
                }
            }
            byte[] completeHash = new byte[aggregateHash.size() + assertionHash.length];
            System.arraycopy(aggregateHash.toByteArray(), 0, completeHash, 0, aggregateHash.size());
            System.arraycopy(assertionHash, 0, completeHash, aggregateHash.size(), assertionHash.length);

            var encodedHash = Base64.getEncoder().encodeToString(completeHash);

            var assertionSigningKey = new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.HS256,
                    tdfObject.aesGcm.getKey());
            if (assertionConfig.signingKey != null && assertionConfig.signingKey.isDefined()) {
                assertionSigningKey = assertionConfig.signingKey;
            }
            var hashValues = new Manifest.Assertion.HashValues(
                    assertionHashAsHex,
                    encodedHash);
            try {
                assertion.sign(hashValues, assertionSigningKey);
            } catch (KeyLengthException e) {
                throw new SDKException("error signing assertion hash", e);
            }
            signedAssertions.add(assertion);
        }

        tdfObject.manifest.assertions = signedAssertions;
        String manifestAsStr = gson.toJson(tdfObject.manifest);

        tdfWriter.appendManifest(manifestAsStr);
        tdfObject.size = tdfWriter.finish();

        return tdfObject;
    }

    static List<String> defaultKases(TDFConfig config) {
        List<String> allk = new ArrayList<>();
        List<String> defk = new ArrayList<>();

        for (KASInfo kasInfo : config.kasInfoList) {
            if (kasInfo.Default != null && kasInfo.Default) {
                defk.add(kasInfo.URL);
            } else if (defk.isEmpty()) {
                allk.add(kasInfo.URL);
            }
        }
        if (defk.isEmpty()) {
            return allk;
        }
        return defk;
    }

    Reader loadTDF(SeekableByteChannel tdf, String platformUrl) throws SDKException, IOException {
        return loadTDF(tdf, Config.newTDFReaderConfig(), platformUrl);
    }

    Reader loadTDF(SeekableByteChannel tdf, Config.TDFReaderConfig tdfReaderConfig, String platformUrl)
            throws SDKException, IOException {
        if (!tdfReaderConfig.ignoreKasAllowlist
                && (tdfReaderConfig.kasAllowlist == null || tdfReaderConfig.kasAllowlist.isEmpty())) {
            ListKeyAccessServersRequest request = ListKeyAccessServersRequest.newBuilder()
                    .build();
            ListKeyAccessServersResponse response;
            try {
                response = RequestHelper.getOrThrow(
                        services.kasRegistry().listKeyAccessServersBlocking(request, Collections.emptyMap()).execute());
            } catch (ConnectException e) {
                throw new SDKException("error getting kas servers", e);
            }
            tdfReaderConfig.kasAllowlist = new HashSet<>();

            for (var entry : response.getKeyAccessServersList()) {
                tdfReaderConfig.kasAllowlist.add(Config.getKasAddress(entry.getUri()));
            }
            tdfReaderConfig.kasAllowlist.add(Config.getKasAddress(platformUrl));
        }
        return loadTDF(tdf, tdfReaderConfig);
    }

    Reader loadTDF(SeekableByteChannel tdf, Config.TDFReaderConfig tdfReaderConfig) throws SDKException, IOException {

        TDFReader tdfReader = new TDFReader(tdf);
        String manifestJson = tdfReader.manifest();
        // use Manifest.readManifest in order to validate the Manifest input
        Manifest manifest = Manifest.readManifest(manifestJson);

        byte[] payloadKey = new byte[GCM_KEY_SIZE];
        String unencryptedMetadata = null;

        Set<String> knownSplits = new HashSet<>();
        Set<String> foundSplits = new HashSet<>();

        Map<Autoconfigure.KeySplitStep, Exception> skippedSplits = new HashMap<>();

        if (manifest.payload.isEncrypted) {
            for (Manifest.KeyAccess keyAccess : manifest.encryptionInformation.keyAccessObj) {
                String splitId = keyAccess.sid == null || keyAccess.sid.isEmpty() ? EMPTY_SPLIT_ID : keyAccess.sid;
                Autoconfigure.KeySplitStep ss = new Autoconfigure.KeySplitStep(keyAccess.url, splitId);
                byte[] unwrappedKey;
                if (foundSplits.contains(ss.splitID)) {
                    continue;
                }
                knownSplits.add(ss.splitID);
                try {
                    var realAddress = Config.getKasAddress(keyAccess.url);
                    if (tdfReaderConfig.ignoreKasAllowlist) {
                        logger.warn("Ignoring KasAllowlist for url {}", realAddress);
                    } else if (tdfReaderConfig.kasAllowlist == null || tdfReaderConfig.kasAllowlist.isEmpty()) {
                        logger.error(
                                "KasAllowlist: No KAS allowlist provided and no KeyAccessServerRegistry available, {} is not allowed",
                                realAddress);
                        throw new SDK.KasAllowlistException(
                                "No KAS allowlist provided and no KeyAccessServerRegistry available");
                    } else if (!tdfReaderConfig.kasAllowlist.contains(realAddress)) {
                        logger.error("KasAllowlist: kas url {} is not allowed", realAddress);
                        throw new SDK.KasAllowlistException("KasAllowlist: kas url " + realAddress + " is not allowed");
                    }
                    unwrappedKey = services.kas().unwrap(keyAccess, manifest.encryptionInformation.policy,
                            tdfReaderConfig.sessionKeyType);
                } catch (Exception e) {
                    skippedSplits.put(ss, e);
                    continue;
                }

                for (int index = 0; index < unwrappedKey.length; index++) {
                    payloadKey[index] ^= unwrappedKey[index];
                }
                foundSplits.add(ss.splitID);

                if (keyAccess.encryptedMetadata != null && !keyAccess.encryptedMetadata.isEmpty()) {
                    AesGcm aesGcm = new AesGcm(unwrappedKey);

                    String decodedMetadata = new String(Base64.getDecoder().decode(keyAccess.encryptedMetadata),
                            StandardCharsets.UTF_8);
                    EncryptedMetadata encryptedMetadata = gson.fromJson(decodedMetadata, EncryptedMetadata.class);

                    var encryptedData = new AesGcm.Encrypted(
                            decoder.decode(encryptedMetadata.ciphertext));

                    byte[] decrypted = aesGcm.decrypt(encryptedData);
                    // this is a little bit weird... the last unencrypted metadata we get from a KAS
                    // is the one
                    // that we return to the user. This is OK because we can't have different
                    // metadata per-KAS
                    unencryptedMetadata = new String(decrypted, StandardCharsets.UTF_8);
                }
            }

            if (knownSplits.size() > foundSplits.size()) {
                List<Exception> exceptionList = new ArrayList<>(skippedSplits.size() + 1);
                exceptionList.add(new Exception("splitKey.unable to reconstruct split key: " + skippedSplits));

                for (Map.Entry<Autoconfigure.KeySplitStep, Exception> entry : skippedSplits.entrySet()) {
                    exceptionList.add(entry.getValue());
                }

                StringBuilder combinedMessage = new StringBuilder();
                for (Exception e : exceptionList) {
                    combinedMessage.append(e.getMessage()).append("\n");
                }

                throw new SDK.SplitKeyException(combinedMessage.toString());
            }
        }

        // Validate root signature
        String rootAlgorithm = manifest.encryptionInformation.integrityInformation.rootSignature.algorithm;
        String rootSignature = manifest.encryptionInformation.integrityInformation.rootSignature.signature;

        ByteArrayOutputStream aggregateHash = new ByteArrayOutputStream();
        for (Manifest.Segment segment : manifest.encryptionInformation.integrityInformation.segments) {
            if (manifest.payload.isEncrypted) {
                byte[] decodedHash = Base64.getDecoder().decode(segment.hash);
                aggregateHash.write(decodedHash);
            } else {
                aggregateHash.write(segment.hash.getBytes());
            }
        }

        String rootSigValue;
        boolean isLegacyTdf = manifest.tdfVersion == null || manifest.tdfVersion.isEmpty();
        if (manifest.payload.isEncrypted) {
            Config.IntegrityAlgorithm sigAlg = Config.IntegrityAlgorithm.HS256;
            if (rootAlgorithm.compareToIgnoreCase(kGmacIntegrityAlgorithm) == 0) {
                sigAlg = Config.IntegrityAlgorithm.GMAC;
            }

            var sig = calculateSignature(aggregateHash.toByteArray(), payloadKey, sigAlg);
            if (isLegacyTdf) {
                sig = Hex.encodeHexString(sig).getBytes();
            }
            rootSigValue = Base64.getEncoder().encodeToString(sig);
        } else {
            MessageDigest digest;
            try {
                digest = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("error getting instance of SHA-256 digest", e);
            }

            rootSigValue = Base64.getEncoder().encodeToString(digest.digest(aggregateHash.toString().getBytes()));
        }

        if (rootSignature.compareTo(rootSigValue) != 0) {
            throw new SDK.RootSignatureValidationException("root signature validation failed");
        }

        int segmentSize = manifest.encryptionInformation.integrityInformation.segmentSizeDefault;
        int encryptedSegSize = manifest.encryptionInformation.integrityInformation.encryptedSegmentSizeDefault;

        if (segmentSize != encryptedSegSize - (kGcmIvSize + kAesBlockSize)) {
            throw new IllegalStateException(
                    "segment size mismatch. encrypted segment size differs from plaintext segment size. the TDF is invalid");
        }

        var aggregateHashByteArrayBytes = aggregateHash.toByteArray();
        // Validate assertions
        for (var assertion : manifest.assertions) {
            // Skip assertion verification if disabled
            if (tdfReaderConfig.disableAssertionVerification) {
                break;
            }

            // Set default to HS256
            var assertionKey = new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.HS256, payloadKey);
            Config.AssertionVerificationKeys assertionVerificationKeys = tdfReaderConfig.assertionVerificationKeys;
            if (!assertionVerificationKeys.isEmpty()) {
                var keyForAssertion = assertionVerificationKeys.getKey(assertion.id);
                if (keyForAssertion != null) {
                    assertionKey = keyForAssertion;
                }
            }

            Manifest.Assertion.HashValues hashValues;
            try {
                hashValues = assertion.verify(assertionKey);
            } catch (ParseException | JOSEException e) {
                throw new SDKException("error validating assertion hash", e);
            }
            var hashOfAssertionAsHex = assertion.hash();

            if (!Objects.equals(hashOfAssertionAsHex, hashValues.getAssertionHash())) {
                throw new SDK.AssertionException("assertion hash mismatch", assertion.id);
            }

            byte[] hashOfAssertion;
            if (isLegacyTdf) {
                hashOfAssertion = hashOfAssertionAsHex.getBytes(StandardCharsets.UTF_8);
            } else {
                try {
                    hashOfAssertion = Hex.decodeHex(hashOfAssertionAsHex);
                } catch (DecoderException e) {
                    throw new SDKException("error decoding assertion hash", e);
                }
            }
            var signature = new byte[aggregateHashByteArrayBytes.length + hashOfAssertion.length];
            System.arraycopy(aggregateHashByteArrayBytes, 0, signature, 0, aggregateHashByteArrayBytes.length);
            System.arraycopy(hashOfAssertion, 0, signature, aggregateHashByteArrayBytes.length, hashOfAssertion.length);
            var encodeSignature = Base64.getEncoder().encodeToString(signature);

            if (!Objects.equals(encodeSignature, hashValues.getSignature())) {
                throw new SDK.AssertionException("failed integrity check on assertion signature", assertion.id);
            }
        }

        return new Reader(tdfReader, manifest, payloadKey, unencryptedMetadata);
    }
}
