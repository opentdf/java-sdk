package io.opentdf.platform.sdk;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;

class PolicyBindingTest {

    @Test
    void knownAnswerLegacyAndHexless() throws Exception {
        // Fixed key: bytes 0..31
        byte[] fixedKey = new byte[32];
        for (int i = 0; i < fixedKey.length; i++) {
            fixedKey[i] = (byte) i;
        }

        String base64Policy = Base64.getEncoder().encodeToString("{\"uuid\":\"test\"}".getBytes(StandardCharsets.UTF_8));

        // Legacy form: Base64(hex(HMAC))
        String legacyHash = TDF.policyBindingHash(fixedKey, base64Policy, false);
        assertEquals(
            "YzFjZTM3OWQ0Y2FiMTZkNmRhNzJkYjllYWQ2NGQ3Y2I0Y2E5YmRhY2FiOGMwNjg1ZmY5MmUzZjc0YWEyYzEyZA==",
            legacyHash,
            "Legacy form should be Base64(hex(HMAC))"
        );

        // Hexless form: Base64(HMAC)
        String hexlessHash = TDF.policyBindingHash(fixedKey, base64Policy, true);
        assertEquals(
            "wc43nUyrFtbactuerWTXy0ypvayrjAaF/5Lj90qiwS0=",
            hexlessHash,
            "Hexless form should be Base64(HMAC)"
        );
    }

    @Test
    void legacyPolicyBindingHashReencodesOnly32ByteBindings() {
        final String raw = "wc43nUyrFtbactuerWTXy0ypvayrjAaF/5Lj90qiwS0=";
        final String legacy = "YzFjZTM3OWQ0Y2FiMTZkNmRhNzJkYjllYWQ2NGQ3Y2I0Y2E5YmRhY2FiOGMwNjg1ZmY5MmUzZjc0YWEyYzEyZA==";

        // Hexless binding (32 bytes) is re-encoded
        assertEquals(legacy, TDF.legacyPolicyBindingHash(raw), "32-byte binding should be re-encoded to legacy form");

        // Legacy binding passes through
        assertEquals(legacy, TDF.legacyPolicyBindingHash(legacy), "Legacy binding should pass through");

        // Invalid base64 passes through
        assertEquals("not!base64", TDF.legacyPolicyBindingHash("not!base64"), "Invalid base64 should pass through");

        // Other lengths pass through
        String other = "AAAAAAAAAAAAAAAAAAAAAA=="; // 16 bytes
        assertEquals(other, TDF.legacyPolicyBindingHash(other), "Non-32-byte binding should pass through");

        // Null passes through
        assertEquals(null, TDF.legacyPolicyBindingHash(null), "Null should return null");
    }
}
