package io.opentdf.platform.sdk;


import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.apache.commons.codec.binary.Hex;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.UUID;
import java.util.List;
import java.util.ArrayList;
import java.util.Random;
import java.util.HexFormat;

public class TDF {

    private static final long MAX_TDF_INPUT_SIZE = 68719476736L;
    private static final int GCM_KEY_SIZE = 32;
    private static final String kSplitKeyType = "split";
    private static final String kWrapped = "wrapped";
    private static final String kKasProtocol = "kas";
    private static final int gcmIvSize  = 12;
    private static final int aesBlockSize = 16;
    private static final String kGCMCipherAlgorithm = "AES-256-GCM";
    private static final int kGMACPayloadLength = 16;
    private static final String kGmacIntegrityAlgorithm = "GMAC";

    private static final String kHmacIntegrityAlgorithm = "HS256";
    private static final String kDefaultMimeType = "application/octet-stream";
    private static final String kTDFAsZip = "zip";
    private static final String kTDFZipReference = "reference";

    public static class DataSizeNotSupported extends Exception {
        public DataSizeNotSupported(String errorMessage) {
            super(errorMessage);
        }
    }

    public static class KasInfoMissing extends Exception {
        public KasInfoMissing(String errorMessage) {
            super(errorMessage);
        }
    }

    public static class KasPublicKeyMissing extends Exception {
        public KasPublicKeyMissing(String errorMessage) {
            super(errorMessage);
        }
    }

    public static class InputStreamReadFailed extends Exception {
        public InputStreamReadFailed(String errorMessage) {
            super(errorMessage);
        }
    }

    public static class FailedToCreateGMAC extends Exception {
        public FailedToCreateGMAC(String errorMessage) {
            super(errorMessage);
        }
    }

    private static class TDFObject {
        public static class EncryptedMetadata {
            private String ciphertext;
            private String iv;
        }

        private Manifest manifest;
        private long size;
        private AesGcm aesGcm;
        private final byte[] payloadKey = new byte[GCM_KEY_SIZE];

        PolicyObject createPolicyObject(List<String> attributes) {
            UUID uuid = UUID.randomUUID();

            PolicyObject policyObject = new PolicyObject();
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

        private void prepareManifest(Config.TDFConfig tdfConfig) throws Exception {
            Gson gson = new GsonBuilder().create();

            manifest.encryptionInformation.keyAccessType = kSplitKeyType;
            manifest.encryptionInformation.keyAccess =  new ArrayList<>();
            manifest.encryptionInformation.integrityInformation = new Manifest.IntegrityInformation();

            PolicyObject policyObject = createPolicyObject(tdfConfig.attributes);
            String base64PolicyObject  = Base64.getEncoder().encodeToString(gson.toJson(policyObject).getBytes(StandardCharsets.UTF_8));
            List<byte[]> symKeys = new ArrayList<>();

            for (Config.KASInfo kasInfo: tdfConfig.kasInfoList) {
                if (kasInfo.PublicKey.isEmpty()) {
                    throw new KasPublicKeyMissing("Kas public key is missing in kas information list");
                }

                // Symmetric key
                Random rd = new Random();
                byte[] symKey = new byte[GCM_KEY_SIZE];
                rd.nextBytes(symKey);

                Manifest.KeyAccess keyAccess = new Manifest.KeyAccess();
                keyAccess.keyType = kWrapped;
                keyAccess.url = kasInfo.URL;
                keyAccess.protocol = kKasProtocol;

                // Add policyBinding
                keyAccess.policyBinding = Hex.encodeHexString(CryptoUtils.CalculateSHA256Hmac(symKey,
                        base64PolicyObject.getBytes(StandardCharsets.UTF_8)));

                // Wrap the key with kas public key
                AsymEncryption asymmetricEncrypt = new AsymEncryption(kasInfo.PublicKey);
                byte[] wrappedKey = asymmetricEncrypt.encrypt(symKey);

                keyAccess.wrappedKey = Base64.getEncoder().encodeToString(wrappedKey);

                // Add meta data
                if (!tdfConfig.metaData.isEmpty()) {
                    AesGcm aesGcm = new AesGcm(symKey);
                    byte[] ciphertext = aesGcm.encrypt(tdfConfig.metaData.getBytes(StandardCharsets.UTF_8));


                    byte[] iv = new byte[AesGcm.GCM_NONCE_LENGTH];
                    System.arraycopy(ciphertext, 0, iv, 0, iv.length);

                    EncryptedMetadata encryptedMetadata = new EncryptedMetadata();
                    encryptedMetadata.ciphertext = new String(ciphertext);
                    encryptedMetadata.iv = new String(iv);

                    keyAccess.encryptedMetadata = gson.toJson(encryptedMetadata);
                }

                symKeys.add(symKey);
                manifest.encryptionInformation.keyAccess.add(keyAccess);
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
            this.manifest = manifest;
        }
    }


    private String calculateSignature(byte[] data, byte[] secret, Config.IntegrityAlgorithm algorithm)
            throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException, FailedToCreateGMAC {
        if (algorithm == Config.IntegrityAlgorithm.HS256) {
            byte[] hmac = CryptoUtils.CalculateSHA256Hmac(secret, data);
            return Hex.encodeHexString(hmac);
        }

        if (kGMACPayloadLength > data.length) {
            throw new FailedToCreateGMAC("Dail to create gmac signature");
        }

        ByteBuffer buffer = ByteBuffer.wrap(data, data.length - kGMACPayloadLength, data.length);
        return Hex.encodeHexString(buffer.array());
    }

    public TDFObject CreateTDF(InputStream inputStream,
                          long inputSize,
                          OutputStream outputStream,
                          Config.TDFConfig tdfConfig) throws Exception {
        if (inputSize > MAX_TDF_INPUT_SIZE) {
            throw new DataSizeNotSupported("can't create tdf larger than 64gb");
        }

        if (tdfConfig.kasInfoList.isEmpty()) {
            throw new KasInfoMissing("kas information is missing");
        }


        // Fetch the kas public keys
        // FetchKasPubKeys();

        TDFObject tdfObject = new TDFObject();
        tdfObject.prepareManifest(tdfConfig);

        int segmentSize = tdfConfig.defaultSegmentSize;
        long totalSegments = inputSize / segmentSize;
        if (inputSize % segmentSize != 0) {
            totalSegments += 1;
        }

        // Empty payload we still want to create a payload
        if (totalSegments == 0) {
            totalSegments = 1;
        }

        long encryptedSegmentSize = segmentSize + gcmIvSize + aesBlockSize;
        long payloadSize = inputSize + (totalSegments * (gcmIvSize + aesBlockSize));
        TDFWriter tdfWriter = new TDFWriter(outputStream);
        tdfWriter.setPayloadSize(payloadSize);

        long readPos = 0;
        StringBuilder aggregateHash = new StringBuilder();
        byte[] readBuf = new byte[tdfConfig.defaultSegmentSize];

        tdfObject.manifest.encryptionInformation.integrityInformation.segments = new ArrayList<>();
        while (totalSegments != 0) {
            long readSize = segmentSize;
            if ((inputSize - readPos) < segmentSize) {
                readSize = inputSize - readPos;
            }

            long n = inputStream.read(readBuf, 0, (int) readSize);
            if (n != readSize) {
                throw new InputStreamReadFailed("Input stream read miss match");
            }

            ByteBuffer readBufView = ByteBuffer.wrap(readBuf, 0, (int) readSize);
            byte[] cipherData = tdfObject.aesGcm.encrypt(readBufView.array());
            tdfWriter.appendPayload(cipherData);

            String segmentSig = calculateSignature(cipherData, tdfObject.payloadKey, tdfConfig.segmentIntegrityAlgorithm);

            aggregateHash.append(segmentSig);
            Manifest.Segment segmentInfo = new Manifest.Segment();
            segmentInfo.hash = Base64.getEncoder().encodeToString(segmentSig.getBytes(StandardCharsets.UTF_8));
            segmentInfo.segmentSize = readSize;
            segmentInfo.encryptedSegmentSize = cipherData.length;

            tdfObject.manifest.encryptionInformation.integrityInformation.segments.add(segmentInfo);

            totalSegments -= 1;
            readPos += readSize;
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

        tdfObject.manifest.encryptionInformation.integrityInformation.segmentSizeDefault = segmentSize;
        tdfObject.manifest.encryptionInformation.integrityInformation.encryptedSegmentSizeDefault = encryptedSegmentSize;

        tdfObject.manifest.encryptionInformation.integrityInformation.segmentHashAlg = kGmacIntegrityAlgorithm;
        if (tdfConfig.segmentIntegrityAlgorithm == Config.IntegrityAlgorithm.HS256) {
            tdfObject.manifest.encryptionInformation.integrityInformation.segmentHashAlg = kHmacIntegrityAlgorithm;
        }

        tdfObject.manifest.encryptionInformation.method.IsStreamable = true;

        // Add payload info
        tdfObject.manifest.payload.mimeType = kDefaultMimeType;
        tdfObject.manifest.payload.protocol = kTDFAsZip;
        tdfObject.manifest.payload.type = kTDFZipReference;
        tdfObject.manifest.payload.url = TDFWriter.TDF_PAYLOAD_FILE_NAME;
        tdfObject.manifest.payload.isEncrypted = true;

        Gson gson = new GsonBuilder().create();
        String manifestAsStr = gson.toJson(tdfObject.manifest);

        tdfWriter.appendManifest(manifestAsStr);
        tdfWriter.finish();

        // TODO: Need to update the size
        //tdfObject.size = tdfWriter.finish();

        return tdfObject;
    }
}
