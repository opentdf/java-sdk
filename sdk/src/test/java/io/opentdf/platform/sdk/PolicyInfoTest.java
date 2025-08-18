package io.opentdf.platform.sdk;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class PolicyInfoTest {
    private PolicyInfo policyInfo;

    @BeforeEach
    void setUp() {
        policyInfo = new PolicyInfo();
    }


    @Test
    void settingAndGettingRemotePolicyUrl() {
        String url = "http://test.com";
        policyInfo.setRemotePolicy(url);
        assertEquals(url, policyInfo.getRemotePolicyUrl());
    }

    @Test
    void gettingRemotePolicyUrlWhenPolicyIsNotRemote() {
        policyInfo.setEmbeddedPlainTextPolicy(new byte[]{1, 2, 3});
        assertThrows(RuntimeException.class, () -> policyInfo.getRemotePolicyUrl());
    }

    @Test
    void settingAndGettingEmbeddedPlainTextPolicy() {
        byte[] policy = new byte[]{1, 2, 3};
        policyInfo.setEmbeddedPlainTextPolicy(policy);
        assertArrayEquals(policy, policyInfo.getEmbeddedPlainTextPolicy());
    }

    @Test
    void gettingEmbeddedPlainTextPolicyWhenPolicyIsNotPlainText() {
        policyInfo.setRemotePolicy("http://test.com");
        assertThrows(RuntimeException.class, () -> policyInfo.getEmbeddedPlainTextPolicy());
    }

    @Test
    void settingAndGettingEmbeddedEncryptedTextPolicy() {
        byte[] policy = new byte[]{1, 2, 3};
        policyInfo.setEmbeddedEncryptedTextPolicy(policy);
        assertArrayEquals(policy, policyInfo.getEmbeddedEncryptedTextPolicy());
    }

    @Test
    void gettingEmbeddedEncryptedTextPolicyWhenPolicyIsNotEncrypted() {
        policyInfo.setRemotePolicy("http://test.com");
        assertThrows(RuntimeException.class, () -> policyInfo.getEmbeddedEncryptedTextPolicy());
    }

    @Test
    void settingAndGettingPolicyBinding() {
        byte[] binding = new byte[]{1, 2, 3};
        policyInfo.setPolicyBinding(binding);
        assertArrayEquals(binding, policyInfo.getPolicyBinding());
    }

    @Test
    void testReadingDEREncodedSignature() throws IOException {
        var curve = NanoTDFType.ECCurve.SECP384R1;
        ByteBuffer buffer = ByteBuffer.allocate(1024);
        buffer.put((byte)2);
        buffer.put(new BigInteger("200", 10).toByteArray());
        buffer.put((byte)3);
        buffer.put(new BigInteger("65536", 10).toByteArray());


        ECCMode eccMode = new ECCMode();
        eccMode.setECDSABinding(true);
        eccMode.setEllipticCurve(curve);

        buffer.flip();

        byte[] signature = PolicyInfo.readBinding(buffer, eccMode);
        assertThat(signature).hasSize(2 * curve.getKeySize());

        var rBytes = new byte[curve.getKeySize()];
        System.arraycopy(signature, 0, rBytes, 0, rBytes.length);
        var r = new BigInteger(1, rBytes);
        assertThat(r).isEqualTo(new BigInteger("200", 10));

        var sBytes = new byte[curve.getKeySize()];
        System.arraycopy(signature, curve.getKeySize(), sBytes, 0, curve.getKeySize());
        var s = new BigInteger(1, sBytes);
        assertThat(s).isEqualTo(new BigInteger("65536", 10));
    }
}