package io.opentdf.platform.sdk;

import org.assertj.core.api.AbstractIterableAssert;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

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


    BigInteger getRandomBigInteger(Random rand, int byteLength) {
        return new BigInteger(1+rand.nextInt(byteLength-1), rand);
    }
    @Test
    void testReadingSignatureWithComponentSizes() {
        var rand = new Random();
        var curve = NanoTDFType.ECCurve.SECP256R1;
        for (var i = 0; i < 100; i++) {
            var rBytes = getRandomBigInteger(rand, curve.getKeySize()).toByteArray();
            var sBytes = getRandomBigInteger(rand, curve.getKeySize()) .toByteArray();
            var buffer = ByteBuffer.allocate(rBytes.length + sBytes.length + 2);
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
            // make sure we read all bytes so that reading continues after us in the TDF
            assertThat(buffer.position()).isEqualTo(buffer.capacity());
        }
    }
}