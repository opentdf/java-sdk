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
        var key = FipsKDF.HKDF_KEY_BUILDER
                .withPrf(FipsKDF.AgreementKDFPRF.SHA256_HMAC)
                .withSalt(salt)
                .build(secret);

        var factory = new FipsKDF.AgreementOperatorFactory();
        KDFCalculator<FipsKDF.AgreementKDFParameters> kdfCalculator = factory.createKDFCalculator(
                FipsKDF.HKDF.withPRF(FipsKDF.AgreementKDFPRF.SHA256_HMAC).using(key.getKey()));
        byte[] hkdf = new byte[32];
        kdfCalculator.generateBytes(hkdf);
        return hkdf;
    }
}
