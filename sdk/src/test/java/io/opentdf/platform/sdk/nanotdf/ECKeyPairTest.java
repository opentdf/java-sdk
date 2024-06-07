package io.opentdf.platform.sdk.nanotdf;

import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

public class ECKeyPairTest {

    public class ECKeys {

        public static final String sdkPublicKey = "-----BEGIN PUBLIC KEY-----\n" +
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXe/Hn2kGc/y1HG5QXDXxor3KbqsW\n" +
                "vFlGGlVDK1RD4qD1HlO8vaXb+JAqNsY31wgbcTNn2TxcV4KR2R7MO2Xgcg==\n" +
                "-----END PUBLIC KEY-----\n";

        public static final String sdkPrivateKey = "-----BEGIN PRIVATE KEY-----\n" +
                "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgKsp9nL8iG6Yd/qOX\n" +
                "DjuArDwjJWhOkHCAmucdwArx1TGgCgYIKoZIzj0DAQehRANCAARd78efaQZz/LUc\n" +
                "blBcNfGivcpuqxa8WUYaVUMrVEPioPUeU7y9pdv4kCo2xjfXCBtxM2fZPFxXgpHZ\n" +
                "Hsw7ZeBy\n" +
                "-----END PRIVATE KEY-----";

        public static final String kasPublicKey = "-----BEGIN PUBLIC KEY-----\n" +
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC4Wmdb7smRiIeA/Zkua2TNj9kySE\n" +
                "8Q2MaJ0kQX9GFePqi5KNDVnjBxQrkHXSTGB7Z/SrRny9vxgo86FT+1aXMQ==\n" +
                "-----END PUBLIC KEY-----";

        public static final String kasPrivateKey = "-----BEGIN PRIVATE KEY-----\n" +
                "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg2Wgo3sPikn/fj9uU\n" +
                "/cU+F4I2rRyOit9/s3fNjHVLxgugCgYIKoZIzj0DAQehRANCAAQLhaZ1vuyZGIh4\n" +
                "D9mS5rZM2P2TJITxDYxonSRBf0YV4+qLko0NWeMHFCuQddJMYHtn9KtGfL2/GCjz\n" +
                "oVP7Vpcx\n" +
                "-----END PRIVATE KEY-----";

        public static final String salt = "L1L";
    }
    @Test
    void ecPublicKeyInPemformat() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            IOException, NoSuchProviderException, InvalidKeySpecException, CertificateException, InvalidKeyException {
        ECKeyPair keyPairA = new ECKeyPair();

        String keypairAPubicKey = keyPairA.publicKeyInPEMFormat();
        String keypairAPrivateKey = keyPairA.privateKeyInPEMFormat();

        ECPublicKey publicKeyA = ECKeyPair.publicKeyFromPem(keypairAPubicKey);
        ECPrivateKey privateKeyA = ECKeyPair.privateKeyFromPem(keypairAPrivateKey);

        System.out.println(keypairAPubicKey);
        System.out.println(keypairAPrivateKey);

        byte[] compressedKey1 = keyPairA.compressECPublickey();
        byte[] compressedKey2 = ECKeyPair.compressECPublickey(keyPairA.publicKeyInPEMFormat());
        assertArrayEquals(compressedKey1, compressedKey2);

        String publicKey = ECKeyPair.publicKeyFromECPoint(compressedKey1,
                ECKeyPair.NanoTDFECCurve.SECP256R1.toString());
        assertEquals(keyPairA.publicKeyInPEMFormat(), publicKey);

        ECKeyPair keyPairB = new ECKeyPair();

        String keypairBPubicKey = keyPairB.publicKeyInPEMFormat();
        String keypairBPrivateKey = keyPairB.privateKeyInPEMFormat();
        System.out.println(keypairBPubicKey);
        System.out.println(keypairBPrivateKey);

        ECPublicKey publicKeyB = ECKeyPair.publicKeyFromPem(keypairBPubicKey);
        ECPrivateKey privateKeyB = ECKeyPair.privateKeyFromPem(keypairBPrivateKey);

        byte[] symmetricKey1 = ECKeyPair.computeECDHKey(publicKeyA, privateKeyB);
        byte[] symmetricKey2 = ECKeyPair.computeECDHKey(publicKeyB, privateKeyA);
        assertArrayEquals(symmetricKey1, symmetricKey2);
        System.out.println(Arrays.toString(symmetricKey1));
    }

    @Test
    void extractPemPubKeyFromX509() throws CertificateException, IOException, NoSuchAlgorithmException,
            InvalidKeySpecException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException {
        String x509ECPubKey = "-----BEGIN CERTIFICATE-----\n" +
                "MIIBCzCBsgIJAK3Uxk7fP5oWMAoGCCqGSM49BAMCMA4xDDAKBgNVBAMMA2thczAe\n" +
                "Fw0yMzA0MjQxNzQ2MTVaFw0yNDA0MjMxNzQ2MTVaMA4xDDAKBgNVBAMMA2thczBZ\n" +
                "MBMGByqGSM49AgEGCCqGSM49AwEHA0IABL//OvkSC1ji2w7AUrj27BxN3K6hhN4B\n" +
                "YRb45lYoMsihIxhDmMDAZTgoaDyNJG59VrJE/yoM9KuiXV8a+82+OwwwCgYIKoZI\n" +
                "zj0EAwIDSAAwRQIhAItk5SmcWSg06tnOCEqTa6UsChaycX/cmAT8PTDRnaRcAiAl\n" +
                "Vr2EvlA2x5mWFE/+nDdxxzljYjLZuSDQMEI/J6u0/Q==\n" +
                "-----END CERTIFICATE-----";
        String pubKey = ECKeyPair.getPEMPublicKeyFromX509Cert(x509ECPubKey);
        System.out.println(pubKey);

        ECPublicKey publicKey = ECKeyPair.publicKeyFromPem(pubKey);
        byte[] compressedKey = publicKey.getQ().getEncoded(true);
        System.out.println(Arrays.toString(compressedKey));

        compressedKey = ECKeyPair.compressECPublickey(pubKey);
        System.out.println(Arrays.toString(compressedKey));
        System.out.println(compressedKey.length);

        ECKeyPair keyPair = new ECKeyPair();

        String keypairPubicKey = keyPair.publicKeyInPEMFormat();
        String keypairPrivateKey = keyPair.privateKeyInPEMFormat();
        System.out.println(keypairPubicKey);
        System.out.println(keypairPrivateKey);

        byte[] symmetricKey = ECKeyPair.computeECDHKey(publicKey, ECKeyPair.privateKeyFromPem(keypairPrivateKey));
        System.out.println(Arrays.toString(symmetricKey));

        byte[] key = ECKeyPair.calculateHKDF(ECKeys.salt.getBytes(StandardCharsets.UTF_8), symmetricKey);
        System.out.println(Arrays.toString(key));
        System.out.println(key.length);
    }

    @Test
    void testECDH()  {
        String expectedKey = "3KGgsptHbTsbxJtql6sHUcx255KcUhxdeJWKjmPMlcc=";

        // SDK side
        ECPublicKey kasPubKey = ECKeyPair.publicKeyFromPem(ECKeys.kasPublicKey);
        ECPrivateKey kasPriKey = ECKeyPair.privateKeyFromPem(ECKeys.kasPrivateKey);

        ECPublicKey sdkPubKey = ECKeyPair.publicKeyFromPem(ECKeys.sdkPublicKey);
        ECPrivateKey sdkPriKey = ECKeyPair.privateKeyFromPem(ECKeys.sdkPrivateKey);

        byte[] symmetricKey = ECKeyPair.computeECDHKey(kasPubKey, sdkPriKey);
        byte[] key = ECKeyPair.calculateHKDF(ECKeys.salt.getBytes(StandardCharsets.UTF_8), symmetricKey);
        String encodedKey = Base64.getEncoder().encodeToString(key);
        assertEquals(encodedKey, expectedKey);

        // KAS side
        symmetricKey = ECKeyPair.computeECDHKey(sdkPubKey, kasPriKey);
        key = ECKeyPair.calculateHKDF(ECKeys.salt.getBytes(StandardCharsets.UTF_8), symmetricKey);
        encodedKey = Base64.getEncoder().encodeToString(key);
        assertEquals(encodedKey, expectedKey);

        byte[] ecPoint = ECKeyPair.compressECPublickey(ECKeys.sdkPublicKey);
        String encodeECPoint = Base64.getEncoder().encodeToString(ecPoint);
        assertEquals(encodeECPoint, "Al3vx59pBnP8tRxuUFw18aK9ym6rFrxZRhpVQytUQ+Kg");

        String publicKey = ECKeyPair.publicKeyFromECPoint(ecPoint,
                ECKeyPair.NanoTDFECCurve.SECP256R1.toString());
        assertArrayEquals(ECKeys.sdkPublicKey.toCharArray(), publicKey.toCharArray());
    }

    @Test
    void testECDSA() {

        String plainText = "Virtru!";
        for (ECKeyPair.NanoTDFECCurve curve: ECKeyPair.NanoTDFECCurve.values()) {

            ECKeyPair keyPair = new ECKeyPair(curve.toString(), ECKeyPair.ECAlgorithm.ECDSA);
            byte[] signature = ECKeyPair.computeECDSASig(plainText.getBytes(), keyPair.getPrivateKey());
            boolean verify = ECKeyPair.verifyECDSAig(plainText.getBytes(), signature, keyPair.getPublicKey());
            assertEquals(verify, true);
        }
    }
}
