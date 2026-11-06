package io.opentdf.platform.sdk;

import io.opentdf.platform.policy.Algorithm;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullSource;

import static io.opentdf.platform.policy.Algorithm.ALGORITHM_EC_P256;
import static io.opentdf.platform.policy.Algorithm.ALGORITHM_EC_P384;
import static io.opentdf.platform.policy.Algorithm.ALGORITHM_EC_P521;
import static io.opentdf.platform.policy.Algorithm.ALGORITHM_HPQT_SECP256R1_MLKEM768;
import static io.opentdf.platform.policy.Algorithm.ALGORITHM_HPQT_SECP384R1_MLKEM1024;
import static io.opentdf.platform.policy.Algorithm.ALGORITHM_HPQT_XWING;
import static io.opentdf.platform.policy.Algorithm.ALGORITHM_MLKEM_1024;
import static io.opentdf.platform.policy.Algorithm.ALGORITHM_MLKEM_768;
import static io.opentdf.platform.policy.Algorithm.ALGORITHM_RSA_2048;
import static io.opentdf.platform.policy.Algorithm.ALGORITHM_RSA_4096;
import static io.opentdf.platform.policy.KasPublicKeyAlgEnum.KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1;
import static io.opentdf.platform.policy.KasPublicKeyAlgEnum.KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP384R1;
import static io.opentdf.platform.policy.KasPublicKeyAlgEnum.KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP521R1;
import static io.opentdf.platform.policy.KasPublicKeyAlgEnum.KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048;
import static io.opentdf.platform.policy.KasPublicKeyAlgEnum.KAS_PUBLIC_KEY_ALG_ENUM_RSA_4096;
import static org.junit.jupiter.api.Assertions.*;

class KeyTypeTest {
    @Test
    void testFromString() {
        assertEquals(KeyType.RSA2048Key, KeyType.fromString("rsa:2048"));
        assertEquals(KeyType.RSA4096Key, KeyType.fromString("rsa:4096"));
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
        assertEquals(KeyType.RSA4096Key, KeyType.fromAlgorithm(ALGORITHM_RSA_4096));
        assertEquals(KeyType.EC256Key, KeyType.fromAlgorithm(ALGORITHM_EC_P256));
        assertEquals(KeyType.EC384Key, KeyType.fromAlgorithm(ALGORITHM_EC_P384));
        assertEquals(KeyType.EC521Key, KeyType.fromAlgorithm(ALGORITHM_EC_P521));
        assertEquals(KeyType.HybridXWingKey, KeyType.fromAlgorithm(ALGORITHM_HPQT_XWING));
        assertEquals(KeyType.HybridSecp256r1MLKEM768Key, KeyType.fromAlgorithm(ALGORITHM_HPQT_SECP256R1_MLKEM768));
        assertEquals(KeyType.HybridSecp384r1MLKEM1024Key, KeyType.fromAlgorithm(ALGORITHM_HPQT_SECP384R1_MLKEM1024));
        assertEquals(KeyType.MLKEM768Key, KeyType.fromAlgorithm(ALGORITHM_MLKEM_768));
        assertEquals(KeyType.MLKEM1024Key, KeyType.fromAlgorithm(ALGORITHM_MLKEM_1024));
    }

    @ParameterizedTest
    @NullSource
    @EnumSource(value = Algorithm.class, names = {"ALGORITHM_UNSPECIFIED", "UNRECOGNIZED"})
    void testFromAlgorithmInvalid(Algorithm algorithm) {
        var failure = assertThrows(IllegalArgumentException.class, () -> KeyType.fromAlgorithm(algorithm));

        assertEquals(algorithm == null ? "Algorithm cannot be null" : "Unsupported algorithm: " + algorithm,
                failure.getMessage());
    }

    @ParameterizedTest
    @CsvSource({"EC256Key, SECP256R1", "EC384Key, SECP384R1", "EC521Key, SECP521R1"})
    void testEcCurve(KeyType keyType, ECCurve expectedCurve) {
        assertTrue(keyType.isEc());
        assertEquals(expectedCurve, keyType.getECCurve());
    }

    @ParameterizedTest
    @EnumSource(value = KeyType.class, names = {"RSA2048Key", "HybridSecp256r1MLKEM768Key"})
    void testNonEcKeyHasNoCurve(KeyType keyType) {
        assertFalse(keyType.isEc());
        assertThrows(IllegalStateException.class, keyType::getECCurve);
    }

    @Test
    void testFromPublicKeyAlgEnum() {
        assertEquals(KeyType.RSA2048Key, KeyType.fromPublicKeyAlgorithm(KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048));
        assertEquals(KeyType.RSA4096Key, KeyType.fromPublicKeyAlgorithm(KAS_PUBLIC_KEY_ALG_ENUM_RSA_4096));
        assertEquals(KeyType.EC256Key, KeyType.fromPublicKeyAlgorithm(KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1));
        assertEquals(KeyType.EC384Key, KeyType.fromPublicKeyAlgorithm(KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP384R1));
        assertEquals(KeyType.EC521Key, KeyType.fromPublicKeyAlgorithm(KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP521R1));
    }
}
