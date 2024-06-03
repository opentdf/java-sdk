package io.opentdf.platform.sdk;

import io.opentdf.platform.sdk.nanotdf.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

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
            InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException,
            UnsupportedNanoTDFFeature {

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
            kasPublicKeyAsPem = kas.getPublicKey(kasInfo);
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

        // Encrypt policy
        PolicyObject policyObject = createPolicyObject(nanoTDFConfig.attributes);
        byte[] policyObjectAsStr = gson.toJson(policyObject).getBytes(StandardCharsets.UTF_8);

        AesGcm gcm = new AesGcm(key);
        int authTagSize = SymmetricAndPayloadConfig.sizeOfAuthTagForCipher(nanoTDFConfig.config.getCipherType());
        byte[] encryptedPolicy = gcm.encrypt(kEmptyIV, authTagSize, policyObjectAsStr, 0, policyObjectAsStr.length);

        PolicyInfo policyInfo = new PolicyInfo();
        byte[] encryptedPolicyWithoutIV = Arrays.copyOfRange(encryptedPolicy, kEmptyIV.length, (encryptedPolicy.length - kEmptyIV.length));
        policyInfo.setEmbeddedEncryptedTextPolicy(encryptedPolicyWithoutIV);

        if (nanoTDFConfig.eccMode.isECDSABindingEnabled()) {
            throw new UnsupportedNanoTDFFeature("ECDSA policy binding is not support");
        } else {
            byte[] gmac = Arrays.copyOfRange(encryptedPolicyWithoutIV, encryptedPolicyWithoutIV.length - kNanoTDFGMACLength,
                    encryptedPolicyWithoutIV.length);
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

        // Encrypt the data
        byte[] actualIV = new byte[kIvPadding + kNanoTDFIvSize];
        byte[] iv = new byte[kNanoTDFIvSize];
        SecureRandom.getInstanceStrong().nextBytes(iv);
        System.arraycopy(iv, 0, actualIV, kIvPadding, iv.length);

        byte[] cipherData = gcm.encrypt(actualIV, authTagSize, data.array(), 0, dataSize);

        // Write the length of the payload as int24
        int cipherDataLengthWithoutPadding = cipherData.length - kIvPadding;
        // int reversedInt = Integer.reverseBytes(cipherDataLengthWithoutPadding);
        byte[] bgIntAsBytes =  ByteBuffer.allocate(4).putInt(cipherDataLengthWithoutPadding).array();
        outputStream.write(bgIntAsBytes, 1, 3);
        nanoTDFSize += 3;

        // Write the payload
        outputStream.write(cipherData, kIvPadding, cipherDataLengthWithoutPadding);
        nanoTDFSize += cipherDataLengthWithoutPadding;

        return nanoTDFSize;
    }

    public void readNanoTDF(ByteBuffer nanoTDF, OutputStream outputStream,
                            SDK.KAS ka) {




        /*

        	header, headerSize, err := NewNanoTDFHeaderFromReader(reader)
	if err != nil {
		return 0, err
	}

	_, err = reader.Seek(0, io.SeekStart)
	if err != nil {
		return 0, fmt.Errorf("readSeeker.Seek failed: %w", err)
	}

	headerBuf := make([]byte, headerSize)
	_, err = reader.Read(headerBuf)
	if err != nil {
		return 0, fmt.Errorf("readSeeker.Seek failed: %w", err)
	}

	kasURL, err := header.kasURL.getURL()
	if err != nil {
		return 0, fmt.Errorf("readSeeker.Seek failed: %w", err)
	}

	encodedHeader := ocrypto.Base64Encode(headerBuf)

	rsaKeyPair, err := ocrypto.NewRSAKeyPair(tdf3KeySize)
	if err != nil {
		return 0, fmt.Errorf("ocrypto.NewRSAKeyPair failed: %w", err)
	}

	client, err := newKASClient(s.dialOptions, s.tokenSource, rsaKeyPair)
	if err != nil {
		return 0, fmt.Errorf("newKASClient failed: %w", err)
	}

	symmetricKey, err := client.unwrapNanoTDF(string(encodedHeader), kasURL)
	if err != nil {
		return 0, fmt.Errorf("readSeeker.Seek failed: %w", err)
	}

	encoded := ocrypto.Base64Encode(symmetricKey)
	slog.Debug("ReadNanoTDF", slog.String("symmetricKey", string(encoded)))

	const (
		kPayloadLoadLengthBufLength = 4
	)
	payloadLengthBuf := make([]byte, kPayloadLoadLengthBufLength)
	_, err = reader.Read(payloadLengthBuf[1:])

	if err != nil {
		return 0, fmt.Errorf(" io.Reader.Read failed :%w", err)
	}

	payloadLength := binary.BigEndian.Uint32(payloadLengthBuf)
	slog.Debug("ReadNanoTDF", slog.Uint64("payloadLength", uint64(payloadLength)))

	cipherDate := make([]byte, payloadLength)
	_, err = reader.Read(cipherDate)
	if err != nil {
		return 0, fmt.Errorf("readSeeker.Seek failed: %w", err)
	}

	aesGcm, err := ocrypto.NewAESGcm(symmetricKey)
	if err != nil {
		return 0, fmt.Errorf("ocrypto.NewAESGcm failed:%w", err)
	}

	ivPadded := make([]byte, 0, ocrypto.GcmStandardNonceSize)
	noncePadding := make([]byte, kIvPadding)
	ivPadded = append(ivPadded, noncePadding...)
	iv := cipherDate[:kNanoTDFIvSize]
	ivPadded = append(ivPadded, iv...)

	tagSize, err := SizeOfAuthTagForCipher(header.sigCfg.cipher)
	if err != nil {
		return 0, fmt.Errorf("SizeOfAuthTagForCipher failed:%w", err)
	}

	decryptedData, err := aesGcm.DecryptWithIVAndTagSize(ivPadded, cipherDate[kNanoTDFIvSize:], tagSize)
	if err != nil {
		return 0, err
	}

	writeLen, err := writer.Write(decryptedData)
	if err != nil {
		return 0, err
	}
	// print(payloadLength)
	// print(string(decryptedData))

	return uint32(writeLen), nil

         */
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
