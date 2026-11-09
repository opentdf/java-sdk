package io.opentdf.platform.sdk;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Section 8 steps 3.3 to 3.9 on hand-built JWS bindings, for the cases the shared vectors do not
 * cover yet: duplicate JOSE members, signature encoding, embedded keys of other key types, and
 * claims other than the two the binding uses.
 */
class AssertionVerifierTest {

    private static final byte[] AGGREGATE = "segment hashes".getBytes(StandardCharsets.US_ASCII);
    private static KeyPair signer;
    private static KeyPair ecKey;
    private static AssertionVerifier.SelectedKey selected;

    @BeforeAll
    static void keys() {
        signer = CryptoUtils.generateRSAKeypair();
        ecKey = CryptoUtils.generateECKeypair(KeyType.EC256Key.getECCurve().getCurveName());
        selected = AssertionVerifier.SelectedKey.rsa((RSAPublicKey) signer.getPublic());
    }

    private static String b64url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String b64url(String text) {
        return b64url(text.getBytes(StandardCharsets.UTF_8));
    }

    private static JsonObject assertion() {
        return JsonParser.parseString("{\"id\":\"a\",\"type\":\"handling\",\"scope\":\"payload\","
                + "\"statement\":{\"format\":\"string\",\"value\":\"SECRET\"}}").getAsJsonObject();
    }

    /** The claims a writer signs for {@link #assertion()}, plus {@code extra} members. */
    private static String claims(String extra) throws Exception {
        String hash = Manifest.Assertion.computeAssertionHash(assertion().toString());
        byte[] hashBytes = Hex.decodeHex(hash);
        byte[] bound = Arrays.copyOf(AGGREGATE, AGGREGATE.length + hashBytes.length);
        System.arraycopy(hashBytes, 0, bound, AGGREGATE.length, hashBytes.length);
        return "{\"assertionHash\":\"" + hash + "\",\"assertionSig\":\"" + Base64.getEncoder().encodeToString(bound)
                + "\"" + extra + "}";
    }

    private static String sign(String headerJson, String claimsJson, PrivateKey key) throws Exception {
        String signingInput = b64url(headerJson) + "." + b64url(claimsJson);
        var signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(key);
        signature.update(signingInput.getBytes(StandardCharsets.US_ASCII));
        return signingInput + "." + b64url(signature.sign());
    }

    private static JsonObject bound(String compactJws) {
        var bound = assertion();
        var binding = new JsonObject();
        binding.addProperty("method", "jws");
        binding.addProperty("signature", compactJws);
        bound.add("binding", binding);
        return bound;
    }

    private static void verify(String compactJws) {
        AssertionVerifier.verifyWithKey(bound(compactJws), "a", selected, AGGREGATE, false);
    }

    private static void assertReason(String compactJws, AssertionFailureReason reason) {
        assertThatThrownBy(() -> verify(compactJws))
                .isInstanceOfSatisfying(SDK.AssertionFailureException.class, e -> {
                    assertThat(e.getReason()).isEqualTo(reason);
                    assertThat(e.getAssertionId()).isEqualTo("a");
                });
    }

    private static String headerWith(String members) {
        return "{\"alg\":\"RS256\"" + members + "}";
    }

    @Test
    void aWellFormedBindingVerifies() throws Exception {
        assertThatCode(() -> verify(sign(headerWith(""), claims(""), signer.getPrivate()))).doesNotThrowAnyException();
    }

    @Test
    void duplicateJoseMembersAreInvalidBindings() throws Exception {
        assertReason(sign("{\"alg\":\"RS256\",\"alg\":\"RS256\"}", claims(""), signer.getPrivate()),
                AssertionFailureReason.INVALID_BINDING);
        assertReason(sign("{\"alg\":\"RS256\",\"\\u0061lg\":\"HS256\"}", claims(""), signer.getPrivate()),
                AssertionFailureReason.INVALID_BINDING);
        String claims = claims("");
        String duplicated = claims.substring(0, claims.length() - 1) + ",\"assertionHash\":\"0\"}";
        assertReason(sign(headerWith(""), duplicated, signer.getPrivate()), AssertionFailureReason.INVALID_BINDING);
    }

    @Test
    void theSignatureSegmentMustBeUnpaddedBase64Url() throws Exception {
        String jws = sign(headerWith(""), claims(""), signer.getPrivate());
        String signature = jws.substring(jws.lastIndexOf('.') + 1);
        String signingInput = jws.substring(0, jws.lastIndexOf('.') + 1);
        byte[] raw = Base64.getUrlDecoder().decode(signature);
        assertReason(signingInput + Base64.getUrlEncoder().encodeToString(raw) + (raw.length % 3 == 0 ? "=" : ""),
                AssertionFailureReason.SIGNATURE_INVALID);
        assertReason(signingInput + Base64.getEncoder().withoutPadding().encodeToString(raw).replace('-', '+') + "+",
                AssertionFailureReason.SIGNATURE_INVALID);
        assertReason(signingInput, AssertionFailureReason.SIGNATURE_INVALID);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            ",\"exp\":1",
            ",\"nbf\":99999999999",
            ",\"iat\":99999999999",
            ",\"aud\":\"someone else\",\"iss\":\"anyone\",\"sub\":5"
    })
    void claimsOtherThanTheBindingsAreIgnored(String extra) throws Exception {
        assertThatCode(() -> verify(sign(headerWith(""), claims(extra), signer.getPrivate()))).doesNotThrowAnyException();
    }

    @Test
    void headerMembersOtherThanTheKeysDoNotMatter() throws Exception {
        assertThatCode(() -> verify(sign(headerWith(",\"kid\":5,\"typ\":{},\"x5u\":\"https://example.com/x\","
                + "\"jku\":\"https://example.com/k\""), claims(""), signer.getPrivate()))).doesNotThrowAnyException();
    }

    private static String ecJwk(ECPublicKey key, String crv) {
        return "{\"kty\":\"EC\",\"crv\":\"" + crv + "\",\"x\":\"" + b64url(coordinate(key.getW().getAffineX()))
                + "\",\"y\":\"" + b64url(coordinate(key.getW().getAffineY())) + "\"}";
    }

    private static byte[] coordinate(BigInteger value) {
        byte[] bytes = value.toByteArray();
        byte[] fixed = new byte[32];
        int copy = Math.min(bytes.length, 32);
        System.arraycopy(bytes, bytes.length - copy, fixed, 32 - copy, copy);
        return fixed;
    }

    private static String ecCertificate() throws Exception {
        var owner = new X500Name("CN=EC");
        var builder = new JcaX509v3CertificateBuilder(owner, BigInteger.ONE,
                new Date(System.currentTimeMillis() - 86_400_000L), new Date(System.currentTimeMillis() + 86_400_000L),
                owner, ecKey.getPublic());
        var certificate = new JcaX509CertificateConverter()
                .getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(ecKey.getPrivate())));
        return Base64.getEncoder().encodeToString(certificate.getEncoded());
    }

    @Test
    void aWellFormedKeyOfAnotherTypeIsNotPermitted() throws Exception {
        var ec = (ECPublicKey) ecKey.getPublic();
        assertReason(sign(headerWith(",\"jwk\":" + ecJwk(ec, "P-256")), claims(""), signer.getPrivate()),
                AssertionFailureReason.SIGNER_NOT_PERMITTED);
        assertReason(sign(headerWith(",\"x5c\":[\"" + ecCertificate() + "\"]"), claims(""), signer.getPrivate()),
                AssertionFailureReason.SIGNER_NOT_PERMITTED);
        // a jwk and an x5c of the same EC key agree with each other
        assertReason(sign(headerWith(",\"jwk\":" + ecJwk(ec, "P-256") + ",\"x5c\":[\"" + ecCertificate() + "\"]"),
                claims(""), signer.getPrivate()), AssertionFailureReason.SIGNER_NOT_PERMITTED);
        String okp = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"" + b64url(new byte[32]) + "\"}";
        assertReason(sign(headerWith(",\"jwk\":" + okp), claims(""), signer.getPrivate()),
                AssertionFailureReason.SIGNER_NOT_PERMITTED);
    }

    @Test
    void anEcJwkThatDisagreesWithTheX5cIsContradictory() throws Exception {
        var other = (ECPublicKey) CryptoUtils.generateECKeypair(KeyType.EC256Key.getECCurve().getCurveName()).getPublic();
        assertReason(sign(headerWith(",\"jwk\":" + ecJwk(other, "P-256") + ",\"x5c\":[\"" + ecCertificate() + "\"]"),
                claims(""), signer.getPrivate()), AssertionFailureReason.INVALID_EMBEDDED_KEY);
    }

    @Test
    void aJwkMalformedForItsKeyTypeIsInvalid() throws Exception {
        var ec = (ECPublicKey) ecKey.getPublic();
        String x = b64url(coordinate(ec.getW().getAffineX()));
        String y = b64url(coordinate(ec.getW().getAffineY()));
        String offCurveY = b64url(coordinate(ec.getW().getAffineY().add(BigInteger.ONE)));
        for (String jwk : new String[] {
                "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + x + "\"}",
                "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + x + "\",\"y\":\"" + offCurveY + "\"}",
                "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + x + "\",\"y\":\"" + y + "=\"}",
                "{\"kty\":\"EC\",\"crv\":\"P-384\",\"x\":\"" + x + "\",\"y\":\"" + y + "\"}",
                "{\"kty\":\"EC\",\"crv\":\"P-257\",\"x\":\"" + x + "\",\"y\":\"" + y + "\"}",
                "{\"kty\":\"EC\",\"x\":\"" + x + "\",\"y\":\"" + y + "\"}",
                "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"" + b64url(new byte[31]) + "\"}",
                "{\"kty\":\"OKP\",\"crv\":\"Ed25519\"}",
                "{\"kty\":\"OKP\",\"crv\":\"P-256\",\"x\":\"" + b64url(new byte[32]) + "\"}",
                "{\"kty\":\"OKP\",\"crv\":\"X25519\",\"x\":\"" + b64url(new byte[32]) + "\"}",
                "{\"kty\":\"XYZ\",\"x\":\"" + x + "\"}",
                "{\"kty\":\"RSA\",\"n\":\"" + b64url(new byte[256]).substring(1) + "+\",\"e\":\"AQAB\"}",
                "{\"kty\":\"RSA\",\"n\":\"\",\"e\":\"AQAB\"}",
                "{\"kty\":5}",
                "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + x + "\",\"y\":\"" + y + "\",\"d\":\"" + x + "\"}",
        }) {
            assertThat(jwk).as("fixture is JSON").satisfies(json -> JsonParser.parseString(json));
            assertThatThrownBy(() -> verify(sign(headerWith(",\"jwk\":" + jwk), claims(""), signer.getPrivate())))
                    .as(jwk)
                    .isInstanceOfSatisfying(SDK.AssertionFailureException.class,
                            e -> assertThat(e.getReason()).isEqualTo(AssertionFailureReason.INVALID_EMBEDDED_KEY));
        }
    }

    private static String rsaJwk(byte[] n, byte[] e) {
        return "{\"kty\":\"RSA\",\"n\":\"" + b64url(n) + "\",\"e\":\"" + b64url(e) + "\"}";
    }

    private static byte[] unsigned(BigInteger value) {
        byte[] bytes = value.toByteArray();
        return bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes;
    }

    private static byte[] withLeadingZero(byte[] bytes) {
        byte[] padded = new byte[bytes.length + 1];
        System.arraycopy(bytes, 0, padded, 1, bytes.length);
        return padded;
    }

    @Test
    void theSelectedKeysJwkMustUseMinimalIntegers() throws Exception {
        var rsa = (RSAPublicKey) signer.getPublic();
        byte[] n = unsigned(rsa.getModulus());
        byte[] e = unsigned(rsa.getPublicExponent());
        String minimal = rsaJwk(n, e);
        assertThatCode(() -> verify(sign(headerWith(",\"jwk\":" + minimal + ",\"kid\":\"anything\""), claims(""),
                signer.getPrivate()))).doesNotThrowAnyException();
        // the same key with a leading zero octet is malformed, never equal to the selected key
        assertReason(sign(headerWith(",\"jwk\":" + rsaJwk(withLeadingZero(n), e)), claims(""), signer.getPrivate()),
                AssertionFailureReason.INVALID_EMBEDDED_KEY);
        assertReason(sign(headerWith(",\"jwk\":" + rsaJwk(n, withLeadingZero(e))), claims(""), signer.getPrivate()),
                AssertionFailureReason.INVALID_EMBEDDED_KEY);
    }

    /** The same bytes, encoded with a non-zero bit after the last whole byte. */
    private static String withTrailingBits(String base64Url) {
        assertThat(base64Url.length() % 4).as("an encoding with spare bits").isNotZero();
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        char last = base64Url.charAt(base64Url.length() - 1);
        String changed = base64Url.substring(0, base64Url.length() - 1) + alphabet.charAt(alphabet.indexOf(last) | 1);
        assertThat(Base64.getUrlDecoder().decode(changed)).isEqualTo(Base64.getUrlDecoder().decode(base64Url));
        return changed;
    }

    @Test
    void base64UrlWithNonZeroTrailingBitsIsRejected() throws Exception {
        // a header whose encoding has spare bits
        String header = headerWith(",\"x\":12");
        String jws = sign(header, claims(""), signer.getPrivate());
        String[] parts = jws.split("\\.");
        assertThatCode(() -> verify(jws)).doesNotThrowAnyException();
        assertReason(withTrailingBits(parts[0]) + "." + parts[1] + "." + parts[2], AssertionFailureReason.INVALID_BINDING);
        assertReason(parts[0] + "." + parts[1] + "." + withTrailingBits(parts[2]), AssertionFailureReason.SIGNATURE_INVALID);

        var rsa = (RSAPublicKey) signer.getPublic();
        String n = b64url(unsigned(rsa.getModulus()));
        String jwk = "{\"kty\":\"RSA\",\"n\":\"" + withTrailingBits(n) + "\",\"e\":\"AQAB\"}";
        assertReason(sign(headerWith(",\"jwk\":" + jwk), claims(""), signer.getPrivate()),
                AssertionFailureReason.INVALID_EMBEDDED_KEY);
    }

    @Test
    void x5cMustBeExactlyOneDerCertificateInStrictBase64() throws Exception {
        byte[] der = TestUtil.createTestCertificate(signer.getPublic(), signer.getPrivate()).getEncoded();
        String leaf = Base64.getEncoder().encodeToString(der);
        assertThatCode(() -> verify(sign(headerWith(",\"x5c\":[\"" + leaf + "\"]"), claims(""), signer.getPrivate())))
                .doesNotThrowAnyException();
        // later elements must decode, but are never parsed
        String notACertificate = Base64.getEncoder().encodeToString("not a certificate".getBytes(StandardCharsets.US_ASCII));
        assertThatCode(() -> verify(sign(headerWith(",\"x5c\":[\"" + leaf + "\",\"" + notACertificate + "\"]"),
                claims(""), signer.getPrivate()))).doesNotThrowAnyException();

        String pem = "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder().encodeToString(der)
                + "\n-----END CERTIFICATE-----\n";
        byte[] trailing = Arrays.copyOf(der, der.length + 2);
        for (String x5c : new String[] {
                "[\"" + Base64.getEncoder().encodeToString(pem.getBytes(StandardCharsets.US_ASCII)) + "\"]",
                "[\"" + Base64.getEncoder().encodeToString(trailing) + "\"]",
                "[\"" + leaf + "\",\"not base64!\"]",
                "[\"" + leaf + "\",5]",
                "[\"" + leaf.replace("=", "") + "\"]",
                "[\"" + Base64.getUrlEncoder().encodeToString(der) + "\"]",
        }) {
            assertThatThrownBy(() -> verify(sign(headerWith(",\"x5c\":" + x5c), claims(""), signer.getPrivate())))
                    .as(x5c.length() > 80 ? x5c.substring(0, 80) : x5c)
                    .isInstanceOfSatisfying(SDK.AssertionFailureException.class,
                            e -> assertThat(e.getReason()).isEqualTo(AssertionFailureReason.INVALID_EMBEDDED_KEY));
        }
    }

    @Test
    void pemTextIsNeverAnHs256Secret() {
        byte[] pem = CryptoUtils.getPublicKeyPEM(signer.getPublic()).getBytes(StandardCharsets.US_ASCII);
        assertThatThrownBy(() -> AssertionVerifier.configuredKey(
                new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.HS256, pem), "a", "the key"))
                .isInstanceOfSatisfying(SDK.AssertionFailureException.class,
                        e -> assertThat(e.getReason()).isEqualTo(AssertionFailureReason.CONFIGURATION_ERROR));
    }
}
