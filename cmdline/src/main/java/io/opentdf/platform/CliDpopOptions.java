package io.opentdf.platform;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import io.opentdf.platform.sdk.DpopKeyValidation;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.UUID;

final class CliDpopOptions {
    private CliDpopOptions() {
    }

    static final class DpopMaterial {
        final JWK jwk;
        final JWSAlgorithm alg;

        DpopMaterial(JWK jwk, JWSAlgorithm alg) {
            // Validate in the constructor so a DpopMaterial is never valid only by
            // convention of its caller — every instance has a compatible key/alg pair.
            DpopKeyValidation.validate(jwk, alg);
            this.jwk = jwk;
            this.alg = alg;
        }
    }

    static Optional<DpopMaterial> parse(String dpopAlg, Path dpopKeyPath) {
        if (dpopKeyPath != null) {
            JWK jwk = loadPrivateKey(dpopKeyPath);
            JWSAlgorithm alg;
            if (dpopAlg != null && !dpopAlg.isEmpty()) {
                alg = parseAlgorithm(dpopAlg);
            } else if (jwk instanceof ECKey) {
                Curve curve = ((ECKey) jwk).getCurve();
                try {
                    alg = DpopKeyValidation.inferEcAlgorithm(curve);
                } catch (IllegalArgumentException e) {
                    throw new IllegalArgumentException(
                            "DPoP key file " + dpopKeyPath + " uses unsupported EC curve " + curve, e);
                }
            } else {
                alg = JWSAlgorithm.RS256;
            }
            try {
                return Optional.of(new DpopMaterial(jwk, alg));
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException(
                        "DPoP key file " + dpopKeyPath + " is incompatible with --dpop=" + alg + ": " + e.getMessage(),
                        e);
            }
        }
        if (dpopAlg != null) {
            JWSAlgorithm alg = dpopAlg.isEmpty() ? JWSAlgorithm.RS256 : parseAlgorithm(dpopAlg);
            return Optional.of(new DpopMaterial(generateKeyForAlgorithm(alg), alg));
        }
        return Optional.empty();
    }

    static JWSAlgorithm parseAlgorithm(String alg) {
        switch (alg.toUpperCase()) {
            case "RS256": return JWSAlgorithm.RS256;
            case "RS384": return JWSAlgorithm.RS384;
            case "RS512": return JWSAlgorithm.RS512;
            case "ES256": return JWSAlgorithm.ES256;
            case "ES384": return JWSAlgorithm.ES384;
            case "ES512": return JWSAlgorithm.ES512;
            default:
                throw new IllegalArgumentException("Unsupported DPoP algorithm: " + alg
                        + ". Supported: RS256, RS384, RS512, ES256, ES384, ES512");
        }
    }

    private static JWK loadPrivateKey(Path path) {
        String pem;
        try {
            pem = Files.readString(path);
        } catch (IOException e) {
            throw new IllegalArgumentException("Cannot read DPoP key file " + path + ": " + e.getMessage(), e);
        }
        JWK jwk;
        try {
            jwk = JWK.parseFromPEMEncodedObjects(pem);
        } catch (JOSEException e) {
            throw new IllegalArgumentException(
                    "DPoP key file " + path + " is not a valid PEM-encoded key: " + e.getMessage(), e);
        }
        if (!jwk.isPrivate()) {
            throw new IllegalArgumentException(
                    "DPoP key file " + path + " contains a public key only; a private key is required");
        }
        return jwk;
    }

    private static JWK generateKeyForAlgorithm(JWSAlgorithm alg) {
        try {
            if (JWSAlgorithm.RS256.equals(alg) || JWSAlgorithm.RS384.equals(alg) || JWSAlgorithm.RS512.equals(alg)) {
                return new RSAKeyGenerator(2048)
                        .keyUse(KeyUse.SIGNATURE)
                        .keyID(UUID.randomUUID().toString())
                        .generate();
            }
            Curve curve;
            if (JWSAlgorithm.ES256.equals(alg)) {
                curve = Curve.P_256;
            } else if (JWSAlgorithm.ES384.equals(alg)) {
                curve = Curve.P_384;
            } else if (JWSAlgorithm.ES512.equals(alg)) {
                curve = Curve.P_521;
            } else {
                throw new IllegalArgumentException("Cannot generate key for algorithm: " + alg);
            }
            return new ECKeyGenerator(curve)
                    .keyUse(KeyUse.SIGNATURE)
                    .keyID(UUID.randomUUID().toString())
                    .generate();
        } catch (JOSEException e) {
            throw new IllegalArgumentException("Failed to generate DPoP key for algorithm " + alg + ": " + e.getMessage(), e);
        }
    }
}
