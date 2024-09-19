package io.opentdf.platform.sdk;

import com.google.gson.Gson;
import com.nimbusds.jose.*;

import io.opentdf.platform.policy.Value;
import io.opentdf.platform.policy.attributes.AttributesServiceGrpc.AttributesServiceFutureStub;
import io.opentdf.platform.sdk.Config.TDFConfig;
import io.opentdf.platform.sdk.Autoconfigure.AttributeValueFQN;
import io.opentdf.platform.sdk.Config.KASInfo;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.erdtman.jcs.JsonCanonicalizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.text.ParseException;
import java.util.*;
import java.util.concurrent.ExecutionException;

public class TDF {

    private final long maximumSize;

    public TDF() {
        this(MAX_TDF_INPUT_SIZE);
    }

    // constructor for tests so that we can set a maximum size that's tractable for
    // tests
    TDF(long maximumInputSize) {
        this.maximumSize = maximumInputSize;
    }

    public static Logger logger = LoggerFactory.getLogger(TDF.class);

    private static final long MAX_TDF_INPUT_SIZE = 68719476736L;
    private static final int GCM_KEY_SIZE = 32;
    private static final String kSplitKeyType = "split";
    private static final String kWrapped = "wrapped";
    private static final String kKasProtocol = "kas";
    private static final int kGcmIvSize = 12;
    private static final int kAesBlockSize = 16;
    private static final String kGCMCipherAlgorithm = "AES-256-GCM";
    private static final int kGMACPayloadLength = 16;
    private static final String kGmacIntegrityAlgorithm = "GMAC";
    private static final String kSha256Hash = "SHA256";

    private static final String kHmacIntegrityAlgorithm = "HS256";
    private static final String kTDFAsZip = "zip";
    private static final String kTDFZipReference = "reference";

    private static final SecureRandom sRandom = new SecureRandom();

    private static final Gson gson = new Gson();

    public class SplitKeyException extends IOException {
        public SplitKeyException(String errorMessage) {
            super(errorMessage);
        }
    }

    public static class DataSizeNotSupported extends RuntimeException {
        public DataSizeNotSupported(String errorMessage) {
            super(errorMessage);
        }
    }

    public static class FailedToCreateEncodedTDF extends RuntimeException {
        public FailedToCreateEncodedTDF(String errorMessage) {
            super(errorMessage);
        }
    }

    public static class KasInfoMissing extends RuntimeException {
        public KasInfoMissing(String errorMessage) {
            super(errorMessage);
        }
    }

    public static class KasPublicKeyMissing extends RuntimeException {
        public KasPublicKeyMissing(String errorMessage) {
            super(errorMessage);
        }
    }

    public static class InputStreamReadFailed extends RuntimeException {
        public InputStreamReadFailed(String errorMessage) {
            super(errorMessage);
        }
    }

    public static class FailedToCreateGMAC extends RuntimeException {
        public FailedToCreateGMAC(String errorMessage) {
            super(errorMessage);
        }
    }

    public static class NotValidateRootSignature extends RuntimeException {
        public NotValidateRootSignature(String errorMessage) {
            super(errorMessage);
        }
    }

    public static class SegmentSizeMismatch extends RuntimeException {
        public SegmentSizeMismatch(String errorMessage) {
            super(errorMessage);
        }
    }

    public static class SegmentSignatureMismatch extends RuntimeException {
        public SegmentSignatureMismatch(String errorMessage) {
            super(errorMessage);
        }
    }

    public static class TDFReadFailed extends RuntimeException {
        public TDFReadFailed(String errorMessage) {
            super(errorMessage);
        }
    }

    public static class EncryptedMetadata {
        private String ciphertext;
        private String iv;
    }

    public static class TDFObject {
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

        PolicyObject createPolicyObject(List<Autoconfigure.AttributeValueFQN> attributes) {
            PolicyObject policyObject = new PolicyObject();
            policyObject.body = new PolicyObject.Body();
            policyObject.uuid = UUID.randomUUID().toString();
            policyObject.body.dataAttributes = new ArrayList<>();
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
            manifest.encryptionInformation.keyAccessType = kSplitKeyType;
            manifest.encryptionInformation.keyAccessObj = new ArrayList<>();

            PolicyObject policyObject = createPolicyObject(tdfConfig.attributes);
            String base64PolicyObject = encoder
                    .encodeToString(gson.toJson(policyObject).getBytes(StandardCharsets.UTF_8));
            List<byte[]> symKeys = new ArrayList<>();
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
                    getKI.Algorithm = "rsa:2048";
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
                var encryptedMetadata = new String();
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
                        throw new KasPublicKeyMissing("Kas public key is missing in kas information list");
                    }

                    // Wrap the key with kas public key
                    AsymEncryption asymmetricEncrypt = new AsymEncryption(kasInfo.PublicKey);
                    byte[] wrappedKey = asymmetricEncrypt.encrypt(symKey);

                    Manifest.KeyAccess keyAccess = new Manifest.KeyAccess();
                    keyAccess.keyType = kWrapped;
                    keyAccess.url = kasInfo.URL;
                    keyAccess.kid = kasInfo.KID;
                    keyAccess.protocol = kKasProtocol;
                    keyAccess.policyBinding = policyBinding;
                    keyAccess.wrappedKey = encoder.encodeToString(wrappedKey);
                    keyAccess.encryptedMetadata = encryptedMetadata;
                    keyAccess.sid = splitID;

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

        public void readPayload(OutputStream outputStream) throws TDFReadFailed,
                FailedToCreateGMAC, SegmentSignatureMismatch, IOException, NoSuchAlgorithmException {

            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            for (Manifest.Segment segment : manifest.encryptionInformation.integrityInformation.segments) {
                byte[] readBuf = new byte[(int) segment.encryptedSegmentSize];
                int bytesRead = tdfReader.readPayloadBytes(readBuf);

                if (readBuf.length != bytesRead) {
                    throw new TDFReadFailed("failed to read payload");
                }

                if (manifest.payload.isEncrypted) {
                    String segHashAlg = manifest.encryptionInformation.integrityInformation.segmentHashAlg;
                    Config.IntegrityAlgorithm sigAlg = Config.IntegrityAlgorithm.HS256;
                    if (segHashAlg.compareToIgnoreCase(kGmacIntegrityAlgorithm) == 0) {
                        sigAlg = Config.IntegrityAlgorithm.GMAC;
                    }

                    var payloadSig = calculateSignature(readBuf, payloadKey, sigAlg);
                    byte[] payloadSigAsBytes = payloadSig.getBytes(StandardCharsets.UTF_8);

                    if (segment.hash.compareTo(Base64.getEncoder().encodeToString(payloadSigAsBytes)) != 0) {
                        throw new SegmentSignatureMismatch("segment signature miss match");
                    }

                    byte[] writeBuf = aesGcm.decrypt(new AesGcm.Encrypted(readBuf));
                    outputStream.write(writeBuf);

                } else {
                    String segmentSig = Hex.encodeHexString(digest.digest(readBuf));
                    if (segment.hash.compareTo(segmentSig) != 0) {
                        throw new SegmentSignatureMismatch("segment signature miss match");
                    }

                    outputStream.write(readBuf);
                }
            }
        }
    }

    private static String calculateSignature(byte[] data, byte[] secret, Config.IntegrityAlgorithm algorithm) {
        if (algorithm == Config.IntegrityAlgorithm.HS256) {
            byte[] hmac = CryptoUtils.CalculateSHA256Hmac(secret, data);
            return Hex.encodeHexString(hmac);
        }

        if (kGMACPayloadLength > data.length) {
            throw new FailedToCreateGMAC("fail to create gmac signature");
        }

        byte[] gmacPayload = Arrays.copyOfRange(data, data.length - kGMACPayloadLength, data.length);
        return Hex.encodeHexString(gmacPayload);
    }

    public TDFObject createTDF(InputStream payload,
            OutputStream outputStream,
            Config.TDFConfig tdfConfig, SDK.KAS kas, AttributesServiceFutureStub attrService)
            throws IOException, JOSEException, AutoConfigureException, InterruptedException, ExecutionException {

        if (tdfConfig.autoconfigure) {
            Autoconfigure.Granter granter = new Autoconfigure.Granter(new ArrayList<>());
            if (tdfConfig.attributeValues != null && !tdfConfig.attributeValues.isEmpty()) {
                granter = Autoconfigure.newGranterFromAttributes(tdfConfig.attributeValues.toArray(new Value[0]));
            } else if (tdfConfig.attributes != null && !tdfConfig.attributes.isEmpty()) {
                granter = Autoconfigure.newGranterFromService(attrService, kas.getKeyCache(),
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
            throw new KasInfoMissing("kas information is missing, no key access template specified or inferred");
        }

        TDFObject tdfObject = new TDFObject();
        tdfObject.prepareManifest(tdfConfig, kas);

        long encryptedSegmentSize = tdfConfig.defaultSegmentSize + kGcmIvSize + kAesBlockSize;
        TDFWriter tdfWriter = new TDFWriter(outputStream);

        StringBuilder aggregateHash = new StringBuilder();
        byte[] readBuf = new byte[tdfConfig.defaultSegmentSize];

        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new SDKException("error creating SHA-256 message digest", e);
        }

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
                    throw new DataSizeNotSupported("can't create tdf larger than 64gb");
                }

                byte[] cipherData;
                String segmentSig;
                Manifest.Segment segmentInfo = new Manifest.Segment();

                // encrypt
                cipherData = tdfObject.aesGcm.encrypt(readBuf, 0, readThisLoop).asBytes();
                payloadOutput.write(cipherData);

                segmentSig = calculateSignature(cipherData, tdfObject.payloadKey, tdfConfig.segmentIntegrityAlgorithm);
                segmentInfo.hash = Base64.getEncoder().encodeToString(segmentSig.getBytes(StandardCharsets.UTF_8));

                aggregateHash.append(segmentSig);
                segmentInfo.segmentSize = readThisLoop;
                segmentInfo.encryptedSegmentSize = cipherData.length;

                tdfObject.manifest.encryptionInformation.integrityInformation.segments.add(segmentInfo);
            } while (!finished);
        }

        Manifest.RootSignature rootSignature = new Manifest.RootSignature();

        String rootSig = calculateSignature(aggregateHash.toString().getBytes(),
                tdfObject.payloadKey, tdfConfig.integrityAlgorithm);
        rootSignature.signature = Base64.getEncoder().encodeToString(rootSig.getBytes(StandardCharsets.UTF_8));

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

        List<Manifest.Assertion> signedAssertions = new ArrayList<>();
        ;
        for (var assertionConfig : tdfConfig.assertionConfigList) {
            var assertion = new Manifest.Assertion();
            assertion.id = assertionConfig.id;
            assertion.type = assertionConfig.type.toString();
            assertion.scope = assertionConfig.scope.toString();
            assertion.statement = assertionConfig.statement;
            assertion.appliesToState = assertionConfig.appliesToState.toString();

            var assertionHash = assertion.hash();
            var completeHashBuilder = new StringBuilder(aggregateHash);
            completeHashBuilder.append(assertionHash);

            var encodedHash = Base64.getEncoder().encodeToString(completeHashBuilder.toString().getBytes());

            var assertionSigningKey = new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.HS256,
                    tdfObject.aesGcm.getKey());
            if (assertionConfig.assertionKey != null && assertionConfig.assertionKey.isDefined()) {
                assertionSigningKey = assertionConfig.assertionKey;
            }

            assertion.sign(new Manifest.Assertion.HashValues(assertionHash, encodedHash), assertionSigningKey);
            signedAssertions.add(assertion);
        }

        tdfObject.manifest.assertions = signedAssertions;
        String manifestAsStr = gson.toJson(tdfObject.manifest);

        tdfWriter.appendManifest(manifestAsStr);
        tdfObject.size = tdfWriter.finish();

        return tdfObject;
    }

    public List<String> defaultKases(TDFConfig config) {
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

    private void fillInPublicKeyInfo(List<Config.KASInfo> kasInfoList, SDK.KAS kas) {
        for (var kasInfo : kasInfoList) {
            if (kasInfo.PublicKey != null && !kasInfo.PublicKey.isBlank()) {
                continue;
            }
            logger.info("no public key provided for KAS at {}, retrieving", kasInfo.URL);
            Config.KASInfo getKasInfo = kas.getPublicKey(kasInfo);
            kasInfo.PublicKey = getKasInfo.PublicKey;
            kasInfo.KID = getKasInfo.KID;
        }
    }

    public Reader loadTDF(SeekableByteChannel tdf, SDK.KAS kas,
            Config.AssertionVerificationKeys... assertionVerificationKeys)
            throws NotValidateRootSignature, SegmentSizeMismatch,
            IOException, FailedToCreateGMAC, JOSEException, ParseException, NoSuchAlgorithmException, DecoderException {

        TDFReader tdfReader = new TDFReader(tdf);
        String manifestJson = tdfReader.manifest();
        Manifest manifest = gson.fromJson(manifestJson, Manifest.class);
        byte[] payloadKey = new byte[GCM_KEY_SIZE];
        String unencryptedMetadata = null;

        Set<String> knownSplits = new HashSet<String>();
        Set<String> foundSplits = new HashSet<String>();
        ;
        Map<Autoconfigure.KeySplitStep, Exception> skippedSplits = new HashMap<>();
        boolean mixedSplits = manifest.encryptionInformation.keyAccessObj.size() > 1 &&
                (manifest.encryptionInformation.keyAccessObj.get(0).sid != null) &&
                !manifest.encryptionInformation.keyAccessObj.get(0).sid.isEmpty();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        if (manifest.payload.isEncrypted) {
            for (Manifest.KeyAccess keyAccess : manifest.encryptionInformation.keyAccessObj) {
                Autoconfigure.KeySplitStep ss = new Autoconfigure.KeySplitStep(keyAccess.url, keyAccess.sid);
                byte[] unwrappedKey;
                if (!mixedSplits) {
                    unwrappedKey = kas.unwrap(keyAccess, manifest.encryptionInformation.policy);
                } else {
                    if (foundSplits.contains(ss.splitID)) {
                        continue;
                    }
                    knownSplits.add(ss.splitID);
                    try {
                        unwrappedKey = kas.unwrap(keyAccess, manifest.encryptionInformation.policy);
                    } catch (Exception e) {
                        skippedSplits.put(ss, e);
                        continue;
                    }
                }

                for (int index = 0; index < unwrappedKey.length; index++) {
                    payloadKey[index] ^= unwrappedKey[index];
                }
                foundSplits.add(ss.splitID);

                if (keyAccess.encryptedMetadata != null && !keyAccess.encryptedMetadata.isEmpty()) {
                    AesGcm aesGcm = new AesGcm(unwrappedKey);

                    String decodedMetadata = new String(Base64.getDecoder().decode(keyAccess.encryptedMetadata),
                            "UTF-8");
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

            if (mixedSplits && knownSplits.size() > foundSplits.size()) {
                List<Exception> exceptionList = new ArrayList<>(skippedSplits.size() + 1);
                exceptionList.add(new Exception("splitKey.unable to reconstruct split key: " + skippedSplits));

                for (Map.Entry<Autoconfigure.KeySplitStep, Exception> entry : skippedSplits.entrySet()) {
                    exceptionList.add(entry.getValue());
                }

                StringBuilder combinedMessage = new StringBuilder();
                for (Exception e : exceptionList) {
                    combinedMessage.append(e.getMessage()).append("\n");
                }

                throw new SplitKeyException(combinedMessage.toString());
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
        if (manifest.payload.isEncrypted) {
            Config.IntegrityAlgorithm sigAlg = Config.IntegrityAlgorithm.HS256;
            if (rootAlgorithm.compareToIgnoreCase(kGmacIntegrityAlgorithm) == 0) {
                sigAlg = Config.IntegrityAlgorithm.GMAC;
            }

            var sig = calculateSignature(aggregateHash.toByteArray(), payloadKey, sigAlg);
            rootSigValue = Base64.getEncoder().encodeToString(sig.getBytes(StandardCharsets.UTF_8));

        } else {
            rootSigValue = Base64.getEncoder().encodeToString(digest.digest(aggregateHash.toString().getBytes()));
        }

        if (rootSignature.compareTo(rootSigValue) != 0) {
            throw new NotValidateRootSignature("root signature validation failed");
        }

        int segmentSize = manifest.encryptionInformation.integrityInformation.segmentSizeDefault;
        int encryptedSegSize = manifest.encryptionInformation.integrityInformation.encryptedSegmentSizeDefault;

        if (segmentSize != encryptedSegSize - (kGcmIvSize + kAesBlockSize)) {
            throw new SegmentSizeMismatch("mismatch encrypted segment size in manifest");
        }

        // Validate assertions
        for (var assertion : manifest.assertions) {
            // Set default to HS256
            var assertionKey = new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.HS256, payloadKey);
            if (assertionVerificationKeys != null && assertionVerificationKeys.length > 0) {
                var keyForAssertion = assertionVerificationKeys[0].getKey(assertion.id);
                if (keyForAssertion != null) {
                    assertionKey = keyForAssertion;
                }
            }

            var hashValues = assertion.verify(assertionKey);
            var assertionAsJson = gson.toJson(assertion);
            JsonCanonicalizer jc = new JsonCanonicalizer(assertionAsJson);
            var hashOfAssertion = Hex.encodeHexString(digest.digest(jc.getEncodedUTF8()));
            var signature = aggregateHash + hashOfAssertion;
            var encodeSignature = Base64.getEncoder().encodeToString(signature.getBytes());

            if (!Objects.equals(hashOfAssertion, hashValues.getAssertionHash())) {
                throw new SDKException("assertion hash mismatch");
            }

            if (!Objects.equals(encodeSignature, hashValues.getSignature())) {
                throw new SDKException("failed integrity check on assertion signature");
            }
        }

        return new Reader(tdfReader, manifest, payloadKey, unencryptedMetadata);
    }
}
