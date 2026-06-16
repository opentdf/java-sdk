package io.opentdf.platform.sdk;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;

final class DpopKeyValidation {
    private DpopKeyValidation() {
    }

    static void validate(JWK jwk, JWSAlgorithm alg) {
        if (jwk == null) {
            throw new IllegalArgumentException("DPoP JWK cannot be null");
        }
        if (alg == null) {
            throw new IllegalArgumentException("DPoP algorithm cannot be null");
        }
        if (jwk instanceof RSAKey) {
            if (!isRsaAlgorithm(alg)) {
                throw new IllegalArgumentException("DPoP algorithm " + alg
                        + " is not compatible with an RSA key; expected one of RS256/RS384/RS512 or PS256/PS384/PS512");
            }
        } else if (jwk instanceof ECKey) {
            JWSAlgorithm expected = inferEcAlgorithm(((ECKey) jwk).getCurve());
            if (!alg.equals(expected)) {
                throw new IllegalArgumentException("DPoP algorithm " + alg
                        + " is not compatible with EC key on curve " + ((ECKey) jwk).getCurve()
                        + "; expected " + expected);
            }
        } else {
            throw new IllegalArgumentException("Unsupported JWK type for DPoP: " + jwk.getKeyType()
                    + "; expected RSA or EC");
        }
    }

    static JWSAlgorithm inferEcAlgorithm(Curve curve) {
        if (Curve.P_256.equals(curve)) {
            return JWSAlgorithm.ES256;
        }
        if (Curve.P_384.equals(curve)) {
            return JWSAlgorithm.ES384;
        }
        if (Curve.P_521.equals(curve)) {
            return JWSAlgorithm.ES512;
        }
        throw new IllegalArgumentException("Unsupported EC curve for DPoP: " + curve);
    }

    private static boolean isRsaAlgorithm(JWSAlgorithm alg) {
        return JWSAlgorithm.RS256.equals(alg) || JWSAlgorithm.RS384.equals(alg) || JWSAlgorithm.RS512.equals(alg)
                || JWSAlgorithm.PS256.equals(alg) || JWSAlgorithm.PS384.equals(alg) || JWSAlgorithm.PS512.equals(alg);
    }
}
