package io.opentdf.platform.sdk.fips.bouncycastle;

import io.opentdf.platform.sdk.HkdfProvider;
import org.bouncycastle.crypto.KDFCalculator;
import org.bouncycastle.crypto.fips.FipsKDF;

/**
 * FIPS 140-approved {@link HkdfProvider} backed by the BouncyCastle FIPS KDF API.
 * Discovered at runtime via {@code META-INF/services/io.opentdf.platform.sdk.HkdfProvider}.
 */
public final class BouncyCastleFipsHkdfProvider implements HkdfProvider {

    @Override
    public byte[] computeHKDF(byte[] salt, byte[] secret) {
        if (secret == null) {
            throw new NullPointerException("secret must not be null");
        }
        // RFC 5869 §2.2: if salt is absent, use a zeroed buffer of HashLen bytes.
        byte[] effectiveSalt = (salt == null || salt.length == 0) ? new byte[32] : salt;
        var key = FipsKDF.HKDF_KEY_BUILDER
                .withPrf(FipsKDF.AgreementKDFPRF.SHA256_HMAC)
                .withSalt(effectiveSalt)
                .build(secret);

        var factory = new FipsKDF.AgreementOperatorFactory();
        KDFCalculator<FipsKDF.AgreementKDFParameters> kdfCalculator = factory.createKDFCalculator(
                FipsKDF.HKDF.withPRF(FipsKDF.AgreementKDFPRF.SHA256_HMAC).using(key.getKey()));
        byte[] hkdf = new byte[32];
        kdfCalculator.generateBytes(hkdf);
        return hkdf;
    }
}
