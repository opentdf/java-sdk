package io.opentdf.platform.sdk;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * An assertion binding is verified only with the key the reader selected for it, and only with
 * that key's algorithm. A jwk or x5c in the binding's JWS header is never used as the
 * verification key.
 */
class AssertionConfiguredKeyTest {

    private static final String ID = "assertion1";

    private static Manifest.Assertion newAssertion() {
        var assertion = new Manifest.Assertion();
        assertion.id = ID;
        assertion.type = AssertionConfig.Type.BaseAssertion.toString();
        assertion.scope = AssertionConfig.Scope.TrustedDataObj.toString();
        assertion.appliesToState = AssertionConfig.AppliesToState.Unencrypted.toString();
        assertion.statement = new AssertionConfig.Statement();
        assertion.statement.format = "string";
        assertion.statement.schema = "text";
        assertion.statement.value = "value";
        return assertion;
    }

    private static Manifest.Assertion signedWith(AssertionConfig.AssertionKey signingKey) throws Exception {
        var assertion = newAssertion();
        assertion.sign(new Manifest.Assertion.HashValues("hash", "sig"), signingKey);
        return assertion;
    }

    /** An assertion whose binding is a JWS with the given header alg, signed by {@code signer}. */
    private static Manifest.Assertion boundWith(JWSAlgorithm alg, com.nimbusds.jose.JWSSigner signer)
            throws Exception {
        var claims = new JWTClaimsSet.Builder()
                .claim("assertionHash", "hash")
                .claim("assertionSig", "sig")
                .build();
        var jwt = new SignedJWT(new JWSHeader(alg), claims);
        jwt.sign(signer);
        var assertion = newAssertion();
        assertion.binding = new Manifest.Binding();
        assertion.binding.method = "jws";
        assertion.binding.signature = jwt.serialize();
        return assertion;
    }

    private static AssertionConfig.AssertionKey rs256(Object key) {
        return new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.RS256, key);
    }

    private static AssertionConfig.AssertionKey hs256(byte[] key) {
        return new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.HS256, key);
    }

    private static byte[] secret(int length) {
        var secret = new byte[length];
        new SecureRandom().nextBytes(secret);
        return secret;
    }

    private static JWK publicJwk(KeyPair keypair) throws Exception {
        return JWK.parse(CryptoUtils.getPublicKeyJWK(keypair.getPublic())).toPublicJWK();
    }

    @Test
    void embeddedJwkOfAnotherKeyDoesNotVerify() throws Exception {
        var configured = CryptoUtils.generateRSAKeypair();
        var other = CryptoUtils.generateRSAKeypair();
        var assertion = signedWith(rs256(other.getPrivate()).withJwk(publicJwk(other)));

        assertThatThrownBy(() -> assertion.verify(rs256(configured.getPublic())))
                .isInstanceOf(SDKException.class);
    }

    @Test
    void embeddedX5cOfAnotherKeyDoesNotVerify() throws Exception {
        var configured = CryptoUtils.generateRSAKeypair();
        var other = CryptoUtils.generateRSAKeypair();
        var cert = TestUtil.createTestCertificate(other.getPublic(), other.getPrivate());
        var x5c = List.of(com.nimbusds.jose.util.Base64.encode(cert.getEncoded()));
        var assertion = signedWith(rs256(other.getPrivate()).withX5c(x5c));

        assertThatThrownBy(() -> assertion.verify(rs256(configured.getPublic())))
                .isInstanceOf(SDKException.class);
    }

    @Test
    void embeddedJwkDoesNotReplaceThePayloadKey() throws Exception {
        // With no key configured, the reader selects the payload key with HS256.
        var signer = CryptoUtils.generateRSAKeypair();
        var assertion = signedWith(rs256(signer.getPrivate()).withJwk(publicJwk(signer)));

        assertThatThrownBy(() -> assertion.verify(hs256(secret(32))))
                .isInstanceOf(SDK.AssertionException.class)
                .hasMessageContaining(ID);
    }

    @Test
    void embeddedJwkOfTheConfiguredKeyVerifies() throws Exception {
        var signer = CryptoUtils.generateRSAKeypair();
        var assertion = signedWith(rs256(signer.getPrivate()).withJwk(publicJwk(signer)));

        var hashValues = assertion.verify(rs256(signer.getPublic()));

        assertThat(hashValues.getAssertionHash()).isEqualTo("hash");
        assertThat(hashValues.getSignature()).isEqualTo("sig");
    }

    @Test
    void headerAlgMustEqualTheRsaKeyAlg() throws Exception {
        var signer = CryptoUtils.generateRSAKeypair();
        for (var alg : List.of(JWSAlgorithm.RS384, JWSAlgorithm.RS512, JWSAlgorithm.PS256)) {
            var assertion = boundWith(alg, new RSASSASigner(signer.getPrivate()));
            assertThatThrownBy(() -> assertion.verify(rs256(signer.getPublic())))
                    .as(alg.getName())
                    .isInstanceOf(SDK.AssertionException.class);
        }
        var control = boundWith(JWSAlgorithm.RS256, new RSASSASigner(signer.getPrivate()));
        assertThat(control.verify(rs256(signer.getPublic())).getAssertionHash()).isEqualTo("hash");
    }

    @Test
    void headerAlgMustEqualTheHmacKeyAlg() throws Exception {
        var key = secret(64);
        for (var alg : List.of(JWSAlgorithm.HS384, JWSAlgorithm.HS512)) {
            var assertion = boundWith(alg, new MACSigner(key));
            assertThatThrownBy(() -> assertion.verify(hs256(key)))
                    .as(alg.getName())
                    .isInstanceOf(SDK.AssertionException.class);
        }
        var control = boundWith(JWSAlgorithm.HS256, new MACSigner(key));
        assertThat(control.verify(hs256(key)).getAssertionHash()).isEqualTo("hash");
    }
}
