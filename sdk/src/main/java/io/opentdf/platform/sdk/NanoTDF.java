package io.opentdf.platform.sdk;

import io.opentdf.platform.sdk.nanotdf.*;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
public class NanoTDF {

    public static Logger logger = LoggerFactory.getLogger(NanoTDF.class);

    public static final byte[] MAGIC_NUMBER_AND_VERSION = new byte[]{0x4C, 0x31, 0x4C};
    private static final int kMaxTDFSize = ((16 * 1024 * 1024) - 3 - 32);  // 16 mb - 3(iv) - 32(max auth tag)
    private static final int kNanoTDFGMACLength = 8;
    private static final int kIvPadding = 9;
    private static final int kNanoTDFIvSize = 3;
    private static final byte[] kEmptyIV = new byte[] { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

    public static class NanoTDFMaxSizeLimit extends Exception {
        public NanoTDFMaxSizeLimit(String errorMessage) {
            super(errorMessage);
        }
    }

    public static class UnsupportedNanoTDFFeature extends Exception {
        public UnsupportedNanoTDFFeature(String errorMessage) {
            super(errorMessage);
        }
    }

    public static class InvalidNanoTDFConfig extends Exception {
        public InvalidNanoTDFConfig(String errorMessage) {
            super(errorMessage);
        }
    }

    public int createNanoTDF(ByteBuffer data, OutputStream outputStream,
                             Config.NanoTDFConfig nanoTDFConfig,
                             SDK.KAS kas) throws IOException, NanoTDFMaxSizeLimit, InvalidNanoTDFConfig,
            NoSuchAlgorithmException, UnsupportedNanoTDFFeature {

        int nanoTDFSize = 0;
        Gson gson = new GsonBuilder().create();

        int dataSize = data.limit();
        if (dataSize > kMaxTDFSize) {
            throw new NanoTDFMaxSizeLimit("exceeds max size for nano tdf");
        }

        if (nanoTDFConfig.kasInfoList.isEmpty()) {
            throw new InvalidNanoTDFConfig("kas url is missing");
        }

        Config.KASInfo kasInfo = nanoTDFConfig.kasInfoList.get(0);
        String url = kasInfo.URL;
        String kasPublicKeyAsPem = kasInfo.PublicKey;
        if (kasPublicKeyAsPem == null || kasPublicKeyAsPem.isEmpty()) {
            logger.info("no public key provided for KAS at {}, retrieving", url);
            kasPublicKeyAsPem = kas.getECPublicKey(kasInfo, nanoTDFConfig.eccMode.getEllipticCurveType());
        }

        // Kas url resource locator
        ResourceLocator kasURL = new ResourceLocator(nanoTDFConfig.kasInfoList.get(0).URL);
        ECKeyPair keyPair = new ECKeyPair(nanoTDFConfig.eccMode.getCurveName(), ECKeyPair.ECAlgorithm.ECDSA);

        // Generate symmetric key
        ECPublicKey kasPublicKey = ECKeyPair.publicKeyFromPem(kasPublicKeyAsPem);
        byte[] symmetricKey = ECKeyPair.computeECDHKey(kasPublicKey, keyPair.getPrivateKey());

        // Generate HKDF key
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashOfSalt = digest.digest(MAGIC_NUMBER_AND_VERSION);
        byte[] key = ECKeyPair.calculateHKDF(hashOfSalt, symmetricKey);
        logger.debug("createNanoTDF key is - {}", Base64.getEncoder().encodeToString(key));

        // Encrypt policy
        PolicyObject policyObject = createPolicyObject(nanoTDFConfig.attributes);
        String policyObjectAsStr = gson.toJson(policyObject);

        logger.debug("createNanoTDF policy object - {}", policyObjectAsStr);

        AesGcm gcm = new AesGcm(key);
        byte[] policyObjectAsBytes = policyObjectAsStr.getBytes(StandardCharsets.UTF_8);
        int authTagSize = SymmetricAndPayloadConfig.sizeOfAuthTagForCipher(nanoTDFConfig.config.getCipherType());
        byte[] encryptedPolicy = gcm.encrypt(kEmptyIV, authTagSize, policyObjectAsBytes, 0, policyObjectAsBytes.length);

        PolicyInfo policyInfo = new PolicyInfo();
        byte[] encryptedPolicyWithoutIV = Arrays.copyOfRange(encryptedPolicy, kEmptyIV.length, encryptedPolicy.length);
        policyInfo.setEmbeddedEncryptedTextPolicy(encryptedPolicyWithoutIV);

        if (nanoTDFConfig.eccMode.isECDSABindingEnabled()) {
            throw new UnsupportedNanoTDFFeature("ECDSA policy binding is not support");
        } else {
            byte[] hash = digest.digest(encryptedPolicyWithoutIV);
            byte[] gmac = Arrays.copyOfRange(hash, hash.length - kNanoTDFGMACLength,
                    hash.length);
            policyInfo.setPolicyBinding(gmac);
        }

        // Create header
        byte[] compressedPubKey = keyPair.compressECPublickey();
        Header header = new Header();
        header.setECCMode(nanoTDFConfig.eccMode);
        header.setPayloadConfig(nanoTDFConfig.config);
        header.setEphemeralKey(compressedPubKey);
        header.setKasLocator(kasURL);

        header.setPolicyInfo(policyInfo);

        int headerSize = header.getTotalSize();
        ByteBuffer bufForHeader = ByteBuffer.allocate(headerSize);
        header.writeIntoBuffer(bufForHeader);

        // Write header
        outputStream.write(bufForHeader.array());
        nanoTDFSize += headerSize;
        logger.debug("createNanoTDF header length {}", headerSize);

        // Encrypt the data
        byte[] actualIV = new byte[kIvPadding + kNanoTDFIvSize];
        byte[] iv = new byte[kNanoTDFIvSize];
        SecureRandom.getInstanceStrong().nextBytes(iv);
        System.arraycopy(iv, 0, actualIV, kIvPadding, iv.length);

        byte[] cipherData = gcm.encrypt(actualIV, authTagSize, data.array(), 0, dataSize);

        // Write the length of the payload as int24
        int cipherDataLengthWithoutPadding = cipherData.length - kIvPadding;
        byte[] bgIntAsBytes =  ByteBuffer.allocate(4).putInt(cipherDataLengthWithoutPadding).array();
        outputStream.write(bgIntAsBytes, 1, 3);
        nanoTDFSize += 3;

        logger.debug("createNanoTDF payload length {}", cipherDataLengthWithoutPadding);

        // Write the payload
        outputStream.write(cipherData, kIvPadding, cipherDataLengthWithoutPadding);
        nanoTDFSize += cipherDataLengthWithoutPadding;

        return nanoTDFSize;
    }

    public void readNanoTDF(ByteBuffer nanoTDF, OutputStream outputStream,
                            SDK.KAS kas) throws IOException {

        Header header = new Header(nanoTDF);

        // create base64 encoded
        byte[] headerData = new byte[header.getTotalSize()];
        header.writeIntoBuffer(ByteBuffer.wrap(headerData));
        String base64HeaderData = Base64.getEncoder().encodeToString(headerData);

        logger.debug("readNanoTDF header length {}", headerData.length);

        String kasUrl = header.getKasLocator().getResourceUrl();

        byte[] key =  kas.unwrapNanoTDF(header.getECCMode().getEllipticCurveType(),
                base64HeaderData,
                kasUrl);
        logger.debug("readNanoTDF key is {}", Base64.getEncoder().encodeToString(key));

        byte[] payloadLengthBuf = new byte[4];
        nanoTDF.get(payloadLengthBuf, 1, 3);
        int payloadLength = ByteBuffer.wrap(payloadLengthBuf).getInt();

        logger.debug("readNanoTDF payload length {}, retrieving", payloadLength);

        // Read iv
        byte[] iv = new byte[kNanoTDFIvSize];
        nanoTDF.get(iv);

        // pad the IV with zero's
        byte[] ivPadded = new byte[AesGcm.GCM_NONCE_LENGTH];
        System.arraycopy(iv, 0, ivPadded, kIvPadding, iv.length);

        byte[] cipherData = new byte[payloadLength - kNanoTDFIvSize];
        nanoTDF.get(cipherData);

        int authTagSize = SymmetricAndPayloadConfig.sizeOfAuthTagForCipher(header.getPayloadConfig().getCipherType());
        AesGcm gcm = new AesGcm(key);
        byte[] plainData = gcm.decrypt(ivPadded, authTagSize, cipherData);

        outputStream.write(plainData);
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
}
