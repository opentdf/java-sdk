package io.opentdf.platform.sdk;


import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

public class TDF {

    private final long maximumSize;

    public TDF() {
        this(MAX_TDF_INPUT_SIZE);
    }

    // constructor for tests so that we can set a maximum size that's tractable for tests
    TDF(long maximumInputSize) {
        this.maximumSize = maximumInputSize;
    }

    public static Logger logger = LoggerFactory.getLogger(TDF.class);

    private static final long MAX_TDF_INPUT_SIZE = 68719476736L;
    private static final int GCM_KEY_SIZE = 32;
    private static final String kSplitKeyType = "split";
    private static final String kWrapped = "wrapped";
    private static final String kKasProtocol = "kas";
    private static final int kGcmIvSize  = 12;
    private static final int kAesBlockSize = 16;
    private static final String kGCMCipherAlgorithm = "AES-256-GCM";
    private static final int kGMACPayloadLength = 16;
    private static final String kGmacIntegrityAlgorithm = "GMAC";

    private static final String kHmacIntegrityAlgorithm = "HS256";
    private static final String kDefaultMimeType = "application/octet-stream";
    private static final String kTDFAsZip = "zip";
    private static final String kTDFZipReference = "reference";

    private static final SecureRandom sRandom = new SecureRandom();
    private static final Gson gson = new GsonBuilder().create();

    public static class DataSizeNotSupported extends RuntimeException {
        public DataSizeNotSupported(String errorMessage) {
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

        PolicyObject createPolicyObject(List<String> attributes) {
            PolicyObject policyObject = new PolicyObject();
            policyObject.body = new PolicyObject.Body();
            policyObject.uuid = UUID.randomUUID().toString();
            policyObject.body.dataAttributes = new ArrayList<>();
            policyObject.body.dissem = new ArrayList<>();

            for (String attribute: attributes) {
                PolicyObject.AttributeObject attributeObject = new PolicyObject.AttributeObject();
                attributeObject.attribute = attribute;
                policyObject.body.dataAttributes.add(attributeObject);
            }
            return policyObject;
        }

        private static final Base64.Encoder encoder = Base64.getEncoder();
        private void prepareManifest(Config.TDFConfig tdfConfig) {
            manifest.encryptionInformation.keyAccessType = kSplitKeyType;
            manifest.encryptionInformation.keyAccessObj =  new ArrayList<>();

            PolicyObject policyObject = createPolicyObject(tdfConfig.attributes);
            String base64PolicyObject  = encoder.encodeToString(gson.toJson(policyObject).getBytes(StandardCharsets.UTF_8));
            List<byte[]> symKeys = new ArrayList<>();

            for (Config.KASInfo kasInfo: tdfConfig.kasInfoList) {
                if (kasInfo.PublicKey == null || kasInfo.PublicKey.isEmpty()) {
                    throw new KasPublicKeyMissing("Kas public key is missing in kas information list");
                }

                // Symmetric key
                byte[] symKey = new byte[GCM_KEY_SIZE];
                sRandom.nextBytes(symKey);

                Manifest.KeyAccess keyAccess = new Manifest.KeyAccess();
                keyAccess.keyType = kWrapped;
                keyAccess.url = kasInfo.URL;
                keyAccess.kid = kasInfo.KID;
                keyAccess.protocol = kKasProtocol;

                // Add policyBinding
                var hexBinding = Hex.encodeHexString(CryptoUtils.CalculateSHA256Hmac(symKey, base64PolicyObject.getBytes(StandardCharsets.UTF_8)));
                keyAccess.policyBinding = encoder.encodeToString(hexBinding.getBytes(StandardCharsets.UTF_8));

                // Wrap the key with kas public key
                AsymEncryption asymmetricEncrypt = new AsymEncryption(kasInfo.PublicKey);
                byte[] wrappedKey = asymmetricEncrypt.encrypt(symKey);

                keyAccess.wrappedKey = encoder.encodeToString(wrappedKey);

                // Add meta data
                if(tdfConfig.metaData != null && !tdfConfig.metaData.trim().isEmpty()) {
                    AesGcm aesGcm = new AesGcm(symKey);
                    var encrypted = aesGcm.encrypt(tdfConfig.metaData.getBytes(StandardCharsets.UTF_8));

                    EncryptedMetadata encryptedMetadata = new EncryptedMetadata();
                    encryptedMetadata.iv = encoder.encodeToString(encrypted.getIv());
                    encryptedMetadata.ciphertext = encoder.encodeToString(encrypted.getCiphertext());

                    var metadata = gson.toJson(encryptedMetadata);
                    keyAccess.encryptedMetadata = encoder.encodeToString(metadata.getBytes(StandardCharsets.UTF_8));
                }

                symKeys.add(symKey);
                manifest.encryptionInformation.keyAccessObj.add(keyAccess);
            }

            manifest.encryptionInformation.policy = base64PolicyObject;
            manifest.encryptionInformation.method.algorithm = kGCMCipherAlgorithm;

            // Create the payload key by XOR all the keys in key access object.
            for (byte[] symKey: symKeys) {
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

        private final String unencryptedMetadata;
        private final AesGcm aesGcm;

        Reader(TDFReader tdfReader, Manifest manifest, byte[] payloadKey, String unencryptedMetadata) {
            this.tdfReader = tdfReader;
            this.manifest = manifest;
            this.aesGcm = new AesGcm(payloadKey);
            this.payloadKey = payloadKey;
            this.unencryptedMetadata = unencryptedMetadata;

        }

        public void readPayload(OutputStream outputStream) throws TDFReadFailed, NoSuchAlgorithmException, InvalidKeyException, FailedToCreateGMAC, SegmentSignatureMismatch, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException, IOException {
            for (Manifest.Segment segment: manifest.encryptionInformation.integrityInformation.segments) {
                byte[] readBuf = new byte[(int)segment.encryptedSegmentSize];
                int bytesRead = tdfReader.readPayloadBytes(readBuf);

                if (readBuf.length != bytesRead) {
                    throw new TDFReadFailed("failed to read payload");
                }

                String segHashAlg = manifest.encryptionInformation.integrityInformation.segmentHashAlg;
                Config.IntegrityAlgorithm sigAlg = Config.IntegrityAlgorithm.HS256;
                if (segHashAlg.compareToIgnoreCase(kGmacIntegrityAlgorithm) == 0) {
                    sigAlg = Config.IntegrityAlgorithm.GMAC;
                }

                String payloadSig = calculateSignature(readBuf, payloadKey, sigAlg);
                byte[] payloadSigAsBytes = payloadSig.getBytes(StandardCharsets.UTF_8);
                if (segment.hash.compareTo(Base64.getEncoder().encodeToString(payloadSigAsBytes)) != 0) {
                    throw new SegmentSignatureMismatch("segment signature miss match");
                }

                byte[] writeBuf = aesGcm.decrypt(new AesGcm.Encrypted(readBuf));
                outputStream.write(writeBuf);
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
                               Config.TDFConfig tdfConfig, SDK.KAS kas) throws IOException {
        if (tdfConfig.kasInfoList.isEmpty()) {
            throw new KasInfoMissing("kas information is missing");
        }

        fillInPublicKeyInfo(tdfConfig.kasInfoList, kas);

        TDFObject tdfObject = new TDFObject();
        tdfObject.prepareManifest(tdfConfig);

        long encryptedSegmentSize = tdfConfig.defaultSegmentSize + kGcmIvSize + kAesBlockSize;
        TDFWriter tdfWriter = new TDFWriter(outputStream);

        StringBuilder aggregateHash = new StringBuilder();
        byte[] readBuf = new byte[tdfConfig.defaultSegmentSize];

        tdfObject.manifest.encryptionInformation.integrityInformation.segments = new ArrayList<>();
        long totalSize = 0;
        boolean finished;
        try (var payloadOutput = tdfWriter.payload()) {
            do {
                int nRead = 0;
                int readThisLoop = 0;
                while (readThisLoop < readBuf.length && (nRead = payload.read(readBuf, readThisLoop, readBuf.length - readThisLoop)) > 0) {
                    readThisLoop += nRead;
                }
                finished = nRead < 0;
                totalSize += readThisLoop;

                if (totalSize > maximumSize) {
                    throw new DataSizeNotSupported("can't create tdf larger than 64gb");
                }
                byte[] cipherData = tdfObject.aesGcm.encrypt(readBuf, 0, readThisLoop).asBytes();
                payloadOutput.write(cipherData);

                String segmentSig = calculateSignature(cipherData, tdfObject.payloadKey, tdfConfig.segmentIntegrityAlgorithm);

                aggregateHash.append(segmentSig);
                Manifest.Segment segmentInfo = new Manifest.Segment();
                segmentInfo.hash = Base64.getEncoder().encodeToString(segmentSig.getBytes(StandardCharsets.UTF_8));
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
        tdfObject.manifest.encryptionInformation.integrityInformation.encryptedSegmentSizeDefault = (int)encryptedSegmentSize;

        tdfObject.manifest.encryptionInformation.integrityInformation.segmentHashAlg = kGmacIntegrityAlgorithm;
        if (tdfConfig.segmentIntegrityAlgorithm == Config.IntegrityAlgorithm.HS256) {
            tdfObject.manifest.encryptionInformation.integrityInformation.segmentHashAlg = kHmacIntegrityAlgorithm;
        }

        tdfObject.manifest.encryptionInformation.method.IsStreamable = true;

        // Add payload info
        tdfObject.manifest.payload = new Manifest.Payload();
        tdfObject.manifest.payload.mimeType = kDefaultMimeType;
        tdfObject.manifest.payload.protocol = kTDFAsZip;
        tdfObject.manifest.payload.type = kTDFZipReference;
        tdfObject.manifest.payload.url = TDFWriter.TDF_PAYLOAD_FILE_NAME;
        tdfObject.manifest.payload.isEncrypted = true;

        String manifestAsStr = gson.toJson(tdfObject.manifest);

        tdfWriter.appendManifest(manifestAsStr);
        tdfObject.size = tdfWriter.finish();

        return tdfObject;
    }

    private void fillInPublicKeyInfo(List<Config.KASInfo> kasInfoList, SDK.KAS kas) {
        for (var kasInfo: kasInfoList) {
            if (kasInfo.PublicKey != null && !kasInfo.PublicKey.isBlank()) {
                continue;
            }
            logger.info("no public key provided for KAS at {}, retrieving", kasInfo.URL);
            kasInfo.PublicKey = kas.getPublicKey(kasInfo);
            kasInfo.KID = kas.getKid(kasInfo);
        }
    }

    public Reader loadTDF(SeekableByteChannel tdf, SDK.KAS kas) throws InvalidAlgorithmParameterException,
            NotValidateRootSignature, SegmentSizeMismatch, NoSuchPaddingException,
            IllegalBlockSizeException, IOException, NoSuchAlgorithmException,
            BadPaddingException, InvalidKeyException, FailedToCreateGMAC {

        TDFReader tdfReader = new TDFReader(tdf);
        String manifestJson = tdfReader.manifest();
        Manifest manifest = gson.fromJson(manifestJson, Manifest.class);
        byte[] payloadKey = new byte[GCM_KEY_SIZE];
        String unencryptedMetadata = null;

        for (Manifest.KeyAccess keyAccess: manifest.encryptionInformation.keyAccessObj) {
            var unwrappedKey = kas.unwrap(keyAccess, manifest.encryptionInformation.policy);
            for (int index = 0; index < unwrappedKey.length; index++) {
                payloadKey[index] ^= unwrappedKey[index];
            }

            if (keyAccess.encryptedMetadata != null && !keyAccess.encryptedMetadata.isEmpty()) {
                AesGcm aesGcm = new AesGcm(unwrappedKey);

                String decodedMetadata = new String(Base64.getDecoder().decode(keyAccess.encryptedMetadata), "UTF-8");
                EncryptedMetadata encryptedMetadata = gson.fromJson(decodedMetadata, EncryptedMetadata.class);

                var encryptedData = new AesGcm.Encrypted(
                    decoder.decode(encryptedMetadata.iv),
                    decoder.decode(encryptedMetadata.ciphertext)
                );

                byte[] decrypted = aesGcm.decrypt(encryptedData);
                // this is a little bit weird... the last unencrypted metadata we get from a KAS is the one
                // that we return to the user. This is OK because we can't have different metadata per-KAS
                unencryptedMetadata = new String(decrypted, StandardCharsets.UTF_8);
            }
        }

        // Validate root signature
        String rootAlgorithm = manifest.encryptionInformation.integrityInformation.rootSignature.algorithm;
        String rootSignature = manifest.encryptionInformation.integrityInformation.rootSignature.signature;

        ByteArrayOutputStream aggregateHash = new ByteArrayOutputStream();
        for (Manifest.Segment segment: manifest.encryptionInformation.integrityInformation.segments) {
            byte[] decodedHash = Base64.getDecoder().decode(segment.hash);
            aggregateHash.write(decodedHash);
        }

        Config.IntegrityAlgorithm sigAlg = Config.IntegrityAlgorithm.HS256;
        if (rootAlgorithm.compareToIgnoreCase(kGmacIntegrityAlgorithm) == 0) {
            sigAlg = Config.IntegrityAlgorithm.GMAC;
        }

        String sig = calculateSignature(aggregateHash.toByteArray(), payloadKey, sigAlg);
        String rootSigValue = Base64.getEncoder().encodeToString(sig.getBytes(StandardCharsets.UTF_8));
        if (rootSignature.compareTo(rootSigValue) != 0) {
            throw new NotValidateRootSignature("root signature validation failed");
        }

        int segmentSize = manifest.encryptionInformation.integrityInformation.segmentSizeDefault;
        int encryptedSegSize = manifest.encryptionInformation.integrityInformation.encryptedSegmentSizeDefault;

        if (segmentSize != encryptedSegSize - (kGcmIvSize + kAesBlockSize)) {
            throw new SegmentSizeMismatch("mismatch encrypted segment size in manifest");
        }

        return new Reader(tdfReader, manifest, payloadKey, unencryptedMetadata);
    }
}