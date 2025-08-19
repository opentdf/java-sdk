package io.opentdf.platform.sdk;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;

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
    void testReadingEncodedSignature() throws IOException {
        var rand = new Random();
        for (var i = 0; i < 100; i++) {
            var curve = NanoTDFType.ECCurve.SECP384R1;
            ByteBuffer buffer = ByteBuffer.allocate(1024);
            var big = 1 + rand.nextInt(Integer.MAX_VALUE - 1);
            var small = 1 + rand.nextInt(Integer.MAX_VALUE >>> 10 - 1);
            int r;
            int s;
            if (rand.nextBoolean()) {
                r = big;
                s = small;
            } else {
                r = small;
                s = big;
            }
            var rBytes = BigInteger.valueOf(r).toByteArray();
            var sBytes = BigInteger.valueOf(s).toByteArray();
            buffer.put((byte)rBytes.length);
            buffer.put(rBytes);
            buffer.put((byte) sBytes.length);
            buffer.put(sBytes);

            var originalSig = Arrays.copyOf(buffer.array(), buffer.position());

            buffer.flip();

            ECCMode eccMode = new ECCMode();
            eccMode.setECDSABinding(true);
            eccMode.setEllipticCurve(curve);

            byte[] signature = PolicyInfo.readBinding(buffer, eccMode);
            assertThat(signature).containsExactly(originalSig);
        }
    }
}