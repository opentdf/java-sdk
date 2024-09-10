package io.opentdf.platform.sdk.nanotdf;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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
}