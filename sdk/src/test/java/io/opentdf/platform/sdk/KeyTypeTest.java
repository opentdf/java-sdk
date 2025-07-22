package io.opentdf.platform.sdk;

import org.junit.jupiter.api.Test;

import static io.opentdf.platform.policy.Algorithm.ALGORITHM_EC_P256;
import static io.opentdf.platform.policy.Algorithm.ALGORITHM_EC_P384;
import static io.opentdf.platform.policy.Algorithm.ALGORITHM_EC_P521;
import static io.opentdf.platform.policy.Algorithm.ALGORITHM_RSA_2048;
import static io.opentdf.platform.policy.KasPublicKeyAlgEnum.KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1;
import static io.opentdf.platform.policy.KasPublicKeyAlgEnum.KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP384R1;
import static io.opentdf.platform.policy.KasPublicKeyAlgEnum.KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP521R1;
import static io.opentdf.platform.policy.KasPublicKeyAlgEnum.KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048;
import static org.junit.jupiter.api.Assertions.*;

class KeyTypeTest {
    @Test
    void testFromString() {
        assertEquals(KeyType.RSA2048Key, KeyType.fromString("rsa:2048"));
        assertEquals(KeyType.EC256Key, KeyType.fromString("ec:secp256r1"));
        assertEquals(KeyType.EC384Key, KeyType.fromString("ec:secp384r1"));
        assertEquals(KeyType.EC521Key, KeyType.fromString("ec:secp521r1"));
    }

    @Test
    void testFromStringInvalid() {
        assertThrows(IllegalArgumentException.class, () -> KeyType.fromString("invalid:key"));
    }

    @Test
    void testFromAlgorithm() {
        assertEquals(KeyType.RSA2048Key, KeyType.fromAlgorithm(ALGORITHM_RSA_2048));
        assertEquals(KeyType.EC256Key, KeyType.fromAlgorithm(ALGORITHM_EC_P256));
        assertEquals(KeyType.EC384Key, KeyType.fromAlgorithm(ALGORITHM_EC_P384));
        assertEquals(KeyType.EC521Key, KeyType.fromAlgorithm(ALGORITHM_EC_P521));
    }

    @Test
    void testFromPublicKeyAlgEnum() {
        assertEquals(KeyType.RSA2048Key, KeyType.fromPublicKeyAlgorithm(KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048));
        assertEquals(KeyType.EC256Key, KeyType.fromPublicKeyAlgorithm(KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1));
        assertEquals(KeyType.EC384Key, KeyType.fromPublicKeyAlgorithm(KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP384R1));
        assertEquals(KeyType.EC521Key, KeyType.fromPublicKeyAlgorithm(KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP521R1));
    }
}