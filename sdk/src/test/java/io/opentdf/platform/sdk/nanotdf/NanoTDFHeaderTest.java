package io.opentdf.platform.sdk.nanotdf;

import io.opentdf.platform.sdk.AesGcm;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import static org.junit.jupiter.api.Assertions.*;

import java.io.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class NanoTDFHeaderTest {

        byte[] binding = new byte[] { (byte) 0x33, (byte) 0x31, (byte) 0x63, (byte) 0x31,
                        (byte) 0x66, (byte) 0x35, (byte) 0x35, (byte) 0x00 };
        String kasUrl = "https://api.example.com/kas";
        String remotePolicyUrl = "https://api-develop01.develop.virtru.com/acm/api/policies/1a1d5e42-bf91-45c7-a86a-61d5331c1f55";

        // Curve - "prime256v1"
        String sdkPrivateKey = "-----BEGIN PRIVATE KEY-----\n" +
                        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1HjFYV8D16BQszNW\n" +
                        "6Hx/JxTE53oqk5/bWaIj4qV5tOyhRANCAAQW1Hsq0tzxN6ObuXqV+JoJN0f78Em/\n" +
                        "PpJXUV02Y6Ex3WlxK/Oaebj8ATsbfaPaxrhyCWB3nc3w/W6+lySlLPn5\n" +
                        "-----END PRIVATE KEY-----";

        String sdkPublicKey = "-----BEGIN PUBLIC KEY-----\n" +
                        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFtR7KtLc8Tejm7l6lfiaCTdH+/BJ\n" +
                        "vz6SV1FdNmOhMd1pcSvzmnm4/AE7G32j2sa4cglgd53N8P1uvpckpSz5+Q==\n" +
                        "-----END PUBLIC KEY-----";

        String kasPrivateKey = "-----BEGIN PRIVATE KEY-----\n" +
                        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu2Hmm80uUzQB1OfB\n" +
                        "PyMhWIyJhPA61v+j0arvcLjTwtqhRANCAASHCLUHY4szFiVV++C9+AFMkEL2gG+O\n" +
                        "byN4Hi7Ywl8GMPOAPcQdIeUkoTd9vub9PcuSj23I8/pLVzs23qhefoUf\n" +
                        "-----END PRIVATE KEY-----";

        String kasPublicKey = "-----BEGIN PUBLIC KEY-----\n" +
                        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhwi1B2OLMxYlVfvgvfgBTJBC9oBv\n" +
                        "jm8jeB4u2MJfBjDzgD3EHSHlJKE3fb7m/T3Lko9tyPP6S1c7Nt6oXn6FHw==\n" +
                        "-----END PUBLIC KEY-----";

        byte[] compressedPubKey = new byte[] {
                        (byte) 0x03, (byte) 0x16, (byte) 0xd4, (byte) 0x7b, (byte) 0x2a, (byte) 0xd2, (byte) 0xdc,
                        (byte) 0xf1,
                        (byte) 0x37, (byte) 0xa3, (byte) 0x9b, (byte) 0xb9, (byte) 0x7a, (byte) 0x95, (byte) 0xf8,
                        (byte) 0x9a,
                        (byte) 0x09, (byte) 0x37, (byte) 0x47, (byte) 0xfb, (byte) 0xf0, (byte) 0x49, (byte) 0xbf,
                        (byte) 0x3e,
                        (byte) 0x92, (byte) 0x57, (byte) 0x51, (byte) 0x5d, (byte) 0x36, (byte) 0x63, (byte) 0xa1,
                        (byte) 0x31,
                        (byte) 0xdd
        };

        byte[] expectedHeader = new byte[] {
                        (byte) 0x4c, (byte) 0x31, (byte) 0x4c, (byte) 0x01, (byte) 0x12, (byte) 0x61, (byte) 0x70,
                        (byte) 0x69, (byte) 0x2e, (byte) 0x65, (byte) 0x78, (byte) 0x61, (byte) 0x6d, (byte) 0x70,
                        (byte) 0x6c, (byte) 0x2e,
                        (byte) 0x63, (byte) 0x6f, (byte) 0x6d, (byte) 0x2f, (byte) 0x6b, (byte) 0x61, (byte) 0x73,
                        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x56, (byte) 0x61, (byte) 0x70,
                        (byte) 0x69, (byte) 0x2d,
                        (byte) 0x64, (byte) 0x65, (byte) 0x76, (byte) 0x65, (byte) 0x6c, (byte) 0x6f, (byte) 0x70,
                        (byte) 0x30, (byte) 0x31, (byte) 0x2e, (byte) 0x64, (byte) 0x65, (byte) 0x76, (byte) 0x65,
                        (byte) 0x6c, (byte) 0x6f,
                        (byte) 0x70, (byte) 0x2e, (byte) 0x76, (byte) 0x69, (byte) 0x72, (byte) 0x74, (byte) 0x72,
                        (byte) 0x75, (byte) 0x2e, (byte) 0x63, (byte) 0x6f, (byte) 0x6d, (byte) 0x2f, (byte) 0x61,
                        (byte) 0x63, (byte) 0x6d,
                        (byte) 0x2f, (byte) 0x61, (byte) 0x70, (byte) 0x69, (byte) 0x2f, (byte) 0x70, (byte) 0x6f,
                        (byte) 0x6c, (byte) 0x69, (byte) 0x63, (byte) 0x69, (byte) 0x65, (byte) 0x73, (byte) 0x2f,
                        (byte) 0x31, (byte) 0x61,
                        (byte) 0x31, (byte) 0x64, (byte) 0x35, (byte) 0x65, (byte) 0x34, (byte) 0x32, (byte) 0x2d,
                        (byte) 0x62, (byte) 0x66, (byte) 0x39, (byte) 0x31, (byte) 0x2d, (byte) 0x34, (byte) 0x35,
                        (byte) 0x63, (byte) 0x37,
                        (byte) 0x2d, (byte) 0x61, (byte) 0x38, (byte) 0x36, (byte) 0x61, (byte) 0x2d, (byte) 0x36,
                        (byte) 0x31, (byte) 0x64, (byte) 0x35, (byte) 0x33, (byte) 0x33, (byte) 0x31, (byte) 0x63,
                        (byte) 0x31, (byte) 0x66,
                        (byte) 0x35, (byte) 0x35, (byte) 0x33, (byte) 0x31, (byte) 0x63, (byte) 0x31, (byte) 0x66,
                        (byte) 0x35, (byte) 0x35, (byte) 0x00, (byte) 0x03, (byte) 0x16, (byte) 0xd4, (byte) 0x7b,
                        (byte) 0x2a, (byte) 0xd2,
                        (byte) 0xdc, (byte) 0xf1, (byte) 0x37, (byte) 0xa3, (byte) 0x9b, (byte) 0xb9, (byte) 0x7a,
                        (byte) 0x95, (byte) 0xf8, (byte) 0x9a, (byte) 0x09, (byte) 0x37, (byte) 0x47, (byte) 0xfb,
                        (byte) 0xf0, (byte) 0x49,
                        (byte) 0xbf, (byte) 0x3e, (byte) 0x92, (byte) 0x57, (byte) 0x51, (byte) 0x5d, (byte) 0x36,
                        (byte) 0x63, (byte) 0xa1, (byte) 0x31, (byte) 0xdd
        };

        // TODO: Need to update the static data to fix this test
        @Test
        public void testNanoTDFHeaderRemotePolicy() throws IOException {
                byte[] headerData = new byte[155];

                // Construct empty header - encrypt use case
                Header header = new Header();

                ResourceLocator kasLocator = new ResourceLocator("https://api.exampl.com/kas");
                header.setKasLocator(kasLocator);

                ECCMode eccMode = new ECCMode((byte) 0x0); // no ecdsa binding and 'secp256r1'
                header.setECCMode(eccMode);

                SymmetricAndPayloadConfig payloadConfig = new SymmetricAndPayloadConfig((byte) 0x0); // no signature and
                                                                                                     // AES_256_GCM_64_TAG
                header.setPayloadConfig(payloadConfig);

                PolicyInfo policyInfo = new PolicyInfo();
                policyInfo.setRemotePolicy(remotePolicyUrl);
                policyInfo.setPolicyBinding(binding);

                header.setPolicyInfo(policyInfo);
                header.setEphemeralKey(compressedPubKey);

                int headerSize = header.getTotalSize();
                headerSize = header.writeIntoBuffer(ByteBuffer.wrap(headerData));
                assertEquals(headerData.length, headerSize);
                assertTrue(Arrays.equals(headerData, expectedHeader));
        }

        // TODO: Need to update the static data to fix this test
        @Test
        public void testNanoTDFReader()
                        throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
                        NoSuchProviderException, CertificateException, InvalidKeyException, InvalidKeySpecException,
                        NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException {

                Header header2 = new Header();
                FileInputStream fileIn = new FileInputStream("src/test/resources/javasdknanotdf.ntdf");
                DataInputStream dataIn = new DataInputStream(fileIn);

                // Read each field of the Header object from the file
                byte[] magicNumberAndVersion = new byte[3]; // size of magic number and version
                dataIn.readFully(magicNumberAndVersion);
                header2.setMagicNumberAndVersion(magicNumberAndVersion);

                NanoTDFType.Protocol protocol = NanoTDFType.Protocol.values()[dataIn.readByte()];

                // Read the body length
                int bodyLength = dataIn.readByte();

                // Read the body
                byte[] body = new byte[bodyLength];
                dataIn.readFully(body);

                // Create a new ResourceLocator object
                ResourceLocator resourceLocator = new ResourceLocator();
                resourceLocator.setProtocol(protocol);
                resourceLocator.setBodyLength(bodyLength);
                resourceLocator.setBody(body);
                header2.setKasLocator(resourceLocator);

                ECCMode eccMode2 = new ECCMode(dataIn.readByte());
                header2.setECCMode(eccMode2);

                SymmetricAndPayloadConfig payloadConfig2 = new SymmetricAndPayloadConfig(dataIn.readByte());
                header2.setPayloadConfig(payloadConfig2);

                // Read the policy type
                int remainingBytes = dataIn.available();

                // Create a byte array to hold the remaining bytes
                byte[] remainingBytesArray = new byte[remainingBytes];

                // Read the remaining bytes into the byte array
                dataIn.readFully(remainingBytesArray);
                PolicyInfo policyInfo = new PolicyInfo(ByteBuffer.wrap(remainingBytesArray), header2.getECCMode());
                header2.setPolicyInfo(policyInfo);

                int sizeToRead = policyInfo.getTotalSize();
                int compressedPubKeySize = ECCMode
                                .getECCompressedPubKeySize(header2.getECCMode().getEllipticCurveType());
                byte[] ephemeralKey = new byte[compressedPubKeySize]; // size of compressed public key
                System.arraycopy(remainingBytesArray, sizeToRead, ephemeralKey, 0, ephemeralKey.length);
                header2.setEphemeralKey(ephemeralKey);

                dataIn.close();
                fileIn.close();

                assertEquals(kasUrl, header2.getKasLocator().getResourceUrl());
        }

        @Test
        public void testNanoTDFEncryption()
                        throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
                        NoSuchProviderException, CertificateException, InvalidKeyException, InvalidKeySpecException,
                        NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException {
                final int kGmacPayloadLength = 8;
                final int nanoTDFIvSize = 3;
                String policy = "{\"body\":{\"dataAttributes\":[],\"dissem\":[\"cn=virtru-user\",\"user@example.com\"]},\"uuid\":\"1a84b9c7-d59c-45ed-b092-c7ed7de73a07\"}";

                // Some buffers for compare.
                byte[] compressedPubKey;
                byte[] headerBuffer;
                byte[] encryptedPayLoad;
                byte[] policyBinding;
                byte[] encryptKey;

                SymmetricAndPayloadConfig payloadConfig = new SymmetricAndPayloadConfig((byte) 0x0);
                int tagSize = SymmetricAndPayloadConfig.sizeOfAuthTagForCipher(payloadConfig.getCipherType());
                byte[] tag = new byte[tagSize];

                ECCMode eccMode = new ECCMode((byte) 0x0); // no ecdsa binding and 'secp256r1'
                ECKeyPair sdkECKeyPair = new ECKeyPair(eccMode.getCurveName(), ECKeyPair.ECAlgorithm.ECDH);
                String sdkPrivateKeyForEncrypt = sdkECKeyPair.privateKeyInPEMFormat();
                String sdkPublicKeyForEncrypt = sdkECKeyPair.publicKeyInPEMFormat();

                ECKeyPair kasECKeyPair = new ECKeyPair(eccMode.getCurveName(), ECKeyPair.ECAlgorithm.ECDH);
                String kasPublicKey = kasECKeyPair.publicKeyInPEMFormat();
                // Encrypt
                Header header = new Header();

                ResourceLocator kasLocator = new ResourceLocator("https://test.com");
                header.setKasLocator(kasLocator);

                header.setECCMode(eccMode);
                header.setPayloadConfig(payloadConfig);

                byte[] secret = ECKeyPair.computeECDHKey(ECKeyPair.publicKeyFromPem(kasPublicKey),
                                ECKeyPair.privateKeyFromPem(sdkPrivateKeyForEncrypt));
                byte[] saltValue = { 'V', 'I', 'R', 'T', 'R', 'U' };
                encryptKey = ECKeyPair.calculateHKDF(saltValue, secret);

                // Encrypt the policy with key from KDF
                int encryptedPayLoadSize = policy.length() + nanoTDFIvSize + tagSize;
                encryptedPayLoad = new byte[encryptedPayLoadSize];

                SecureRandom secureRandom = new SecureRandom();
                byte[] iv = new byte[nanoTDFIvSize];
                secureRandom.nextBytes(iv);

                // Adjust the span to add the IV vector at the start of the buffer
                byte[] encryptBufferSpan = Arrays.copyOfRange(encryptedPayLoad, nanoTDFIvSize, encryptedPayLoad.length);

                AesGcm encoder = new AesGcm(encryptKey);
                encoder.encrypt(encryptBufferSpan);

                byte[] authTag = new byte[tag.length];
                // encoder.finish(authTag);

                // Copy IV at start
                System.arraycopy(iv, 0, encryptedPayLoad, 0, iv.length);

                // Copy tag at end
                System.arraycopy(tag, 0, encryptedPayLoad, nanoTDFIvSize + policy.length(), tag.length);

                // Create an encrypted policy.
                PolicyInfo encryptedPolicy = new PolicyInfo();
                encryptedPolicy.setEmbeddedEncryptedTextPolicy(encryptedPayLoad);

                byte[] digest = encryptedPayLoad;
                if (eccMode.isECDSABindingEnabled()) {
                        // Calculate the ecdsa binding.
                        policyBinding = ECKeyPair.computeECDSASig(digest,
                                        ECKeyPair.privateKeyFromPem(sdkPrivateKeyForEncrypt));
                        encryptedPolicy.setPolicyBinding(policyBinding);
                } else {
                        // Calculate the gmac binding
                        byte[] gmac = Arrays.copyOfRange(digest, digest.length - kGmacPayloadLength, digest.length);
                        encryptedPolicy.setPolicyBinding(gmac);
                }

                header.setPolicyInfo(encryptedPolicy);

                compressedPubKey = ECKeyPair.compressECPublickey(sdkPublicKeyForEncrypt);
                header.setEphemeralKey(compressedPubKey);

                int headerSize = header.getTotalSize();
                headerBuffer = new byte[headerSize];
                int sizeWritten = header.writeIntoBuffer(ByteBuffer.wrap(headerBuffer));
                assertEquals(sizeWritten, headerSize);
        }
}
