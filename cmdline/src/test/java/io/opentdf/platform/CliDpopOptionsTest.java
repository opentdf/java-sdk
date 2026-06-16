package io.opentdf.platform;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CliDpopOptionsTest {

    @Test
    void parse_returnsEmpty_whenNeitherFlagSet() {
        assertThat(CliDpopOptions.parse(null, null)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"})
    void parse_generatesKeyForExplicitAlgorithm(String alg) {
        Optional<CliDpopOptions.DpopMaterial> result = CliDpopOptions.parse(alg, null);
        assertThat(result).isPresent();
        assertThat(result.get().alg).isEqualTo(JWSAlgorithm.parse(alg));
        assertThat(result.get().jwk.isPrivate()).isTrue();
    }

    @Test
    void parse_defaultsToRs256_whenDpopFlagWithoutValue() {
        Optional<CliDpopOptions.DpopMaterial> result = CliDpopOptions.parse("", null);
        assertThat(result).isPresent();
        assertThat(result.get().alg).isEqualTo(JWSAlgorithm.RS256);
        assertThat(result.get().jwk).isInstanceOf(RSAKey.class);
    }

    @Test
    void parse_throwsForUnsupportedAlgorithm() {
        assertThatThrownBy(() -> CliDpopOptions.parse("HS256", null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsupported DPoP algorithm")
                .hasMessageContaining("HS256");
    }

    @Test
    void parse_throwsForMissingKeyFile() {
        Path nonexistent = Path.of("/tmp/definitely-does-not-exist-" + UUID.randomUUID() + ".pem");
        assertThatThrownBy(() -> CliDpopOptions.parse(null, nonexistent))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Cannot read DPoP key file")
                .hasMessageContaining(nonexistent.toString());
    }

    @Test
    void parse_throwsForMalformedPem(@TempDir Path tmp) throws Exception {
        Path badPem = tmp.resolve("bad.pem");
        Files.writeString(badPem, "this is not a PEM file");
        assertThatThrownBy(() -> CliDpopOptions.parse(null, badPem))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not a valid PEM-encoded key");
    }

    @Test
    void parse_throwsForPublicKeyOnlyPem(@TempDir Path tmp) throws Exception {
        RSAKey rsa = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();
        Path publicOnly = tmp.resolve("public.pem");
        Files.writeString(publicOnly, encodePublicKey(rsa));
        assertThatThrownBy(() -> CliDpopOptions.parse(null, publicOnly))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("public key only")
                .hasMessageContaining("private key is required");
    }

    @Test
    void parse_acceptsRsaPrivateKeyPemAndDefaultsToRs256(@TempDir Path tmp) throws Exception {
        RSAKey rsa = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();
        Path keyFile = tmp.resolve("rsa.pem");
        Files.writeString(keyFile, encodePrivateKey(rsa.toPrivateKey().getEncoded()));

        Optional<CliDpopOptions.DpopMaterial> result = CliDpopOptions.parse(null, keyFile);
        assertThat(result).isPresent();
        assertThat(result.get().alg).isEqualTo(JWSAlgorithm.RS256);
        assertThat(result.get().jwk).isInstanceOf(RSAKey.class);
        assertThat(result.get().jwk.isPrivate()).isTrue();
    }

    @Test
    void parse_acceptsEcPrivateKeyAndInfersAlgorithm(@TempDir Path tmp) throws Exception {
        ECKey ec = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();
        Path keyFile = tmp.resolve("ec.pem");
        Files.writeString(keyFile, encodeEcKeyPair(ec));

        Optional<CliDpopOptions.DpopMaterial> result = CliDpopOptions.parse(null, keyFile);
        assertThat(result).isPresent();
        assertThat(result.get().alg).isEqualTo(JWSAlgorithm.ES256);
        assertThat(result.get().jwk).isInstanceOf(ECKey.class);
    }

    @Test
    void parse_rejectsRsaKeyWithEcAlgorithm(@TempDir Path tmp) throws Exception {
        RSAKey rsa = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();
        Path keyFile = tmp.resolve("rsa.pem");
        Files.writeString(keyFile, encodePrivateKey(rsa.toPrivateKey().getEncoded()));

        assertThatThrownBy(() -> CliDpopOptions.parse("ES256", keyFile))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("incompatible with --dpop=ES256");
    }

    @Test
    void parse_explicitAlgorithmOverridesEcInferenceWhenCompatible(@TempDir Path tmp) throws Exception {
        ECKey ec = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();
        Path keyFile = tmp.resolve("ec.pem");
        Files.writeString(keyFile, encodeEcKeyPair(ec));

        Optional<CliDpopOptions.DpopMaterial> result = CliDpopOptions.parse("ES256", keyFile);
        assertThat(result).isPresent();
        assertThat(result.get().alg).isEqualTo(JWSAlgorithm.ES256);
    }

    private static String encodePrivateKey(byte[] pkcs8) {
        String base64 = java.util.Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(pkcs8);
        return "-----BEGIN PRIVATE KEY-----\n" + base64 + "\n-----END PRIVATE KEY-----\n";
    }

    private static String encodePublicKey(RSAKey key) throws Exception {
        byte[] x509 = key.toPublicKey().getEncoded();
        String base64 = java.util.Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(x509);
        return "-----BEGIN PUBLIC KEY-----\n" + base64 + "\n-----END PUBLIC KEY-----\n";
    }

    private static String encodeEcKeyPair(ECKey ec) throws Exception {
        byte[] pubX509 = ec.toPublicKey().getEncoded();
        byte[] privPkcs8 = ec.toPrivateKey().getEncoded();
        String pubB64 = java.util.Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(pubX509);
        String privB64 = java.util.Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(privPkcs8);
        return "-----BEGIN PUBLIC KEY-----\n" + pubB64 + "\n-----END PUBLIC KEY-----\n"
                + "-----BEGIN PRIVATE KEY-----\n" + privB64 + "\n-----END PRIVATE KEY-----\n";
    }
}
