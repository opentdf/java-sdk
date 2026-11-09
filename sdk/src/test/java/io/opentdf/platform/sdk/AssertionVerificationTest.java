package io.opentdf.platform.sdk;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Assertion verification on read: the key is selected once from the reader's configuration
 * (per-ID key, then default key, then the payload key with HS256), keys embedded in the JWS
 * header never add trust, and the hash covers the assertion as received.
 * <p>
 * Every negative case has a positive control showing that the same reader configuration accepts
 * the authorized signer.
 */
class AssertionVerificationTest {

    private static final String KAS_URL = "https://example.com/kas0";
    private static final String ID = "assertion1";
    private static final byte[] PLAINTEXT = "assertion verification".getBytes(StandardCharsets.UTF_8);

    private static KeyPair kasKeyPair;
    /** The signer the reader is configured with. */
    private static KeyPair issuer;
    /** A key the reader is not configured with. */
    private static KeyPair unrelated;

    private static final SDK.KAS KAS = new SDK.KAS() {
        @Override
        public void close() {
            // nothing to release
        }

        @Override
        public Config.KASInfo getPublicKey(Config.KASInfo kasInfo) {
            var resolved = new Config.KASInfo();
            resolved.URL = kasInfo.URL;
            resolved.KID = "r1";
            resolved.PublicKey = CryptoUtils.getPublicKeyPEM(kasKeyPair.getPublic());
            return resolved;
        }

        @Override
        public byte[] unwrap(Manifest.KeyAccess keyAccess, String policy, KeyType sessionKeyType) {
            return new AsymDecryption(kasKeyPair.getPrivate()).decrypt(Base64.getDecoder().decode(keyAccess.wrappedKey));
        }

        @Override
        public KASKeyCache getKeyCache() {
            return new KASKeyCache();
        }
    };

    @BeforeAll
    static void generateKeys() {
        kasKeyPair = CryptoUtils.generateRSAKeypair();
        issuer = CryptoUtils.generateRSAKeypair();
        unrelated = CryptoUtils.generateRSAKeypair();
    }

    // ------------------------------------------------------------------ fixtures

    private static AssertionConfig assertionConfig(String id, AssertionConfig.AssertionKey signingKey) {
        var config = new AssertionConfig();
        config.id = id;
        config.type = AssertionConfig.Type.HandlingAssertion;
        config.scope = AssertionConfig.Scope.Payload;
        config.appliesToState = AssertionConfig.AppliesToState.Unencrypted;
        config.statement = new AssertionConfig.Statement();
        config.statement.format = "json+stanag5636";
        config.statement.schema = "urn:nato:stanag:5636:A:1:elements:json";
        config.statement.value = "{\"ocl\":{\"cls\":\"SECRET\"}}";
        config.signingKey = signingKey;
        return config;
    }

    private static AssertionConfig.AssertionKey issuerSigningKey() {
        return new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.RS256, issuer.getPrivate());
    }

    private static byte[] createTdf(AssertionConfig... assertions) throws IOException {
        var kasInfo = new Config.KASInfo();
        kasInfo.URL = KAS_URL;
        var out = new ByteArrayOutputStream();
        new TDF(new FakeServicesBuilder().setKas(KAS).build()).createTDF(new ByteArrayInputStream(PLAINTEXT), out,
                Config.newTDFConfig(Config.withAutoconfigure(false), Config.withKasInformation(kasInfo),
                        Config.withAssertionConfig(assertions)));
        return out.toByteArray();
    }

    private static TDF.Reader load(byte[] tdf, Config.AssertionVerificationKeys keys) throws IOException {
        var options = new ArrayList<Consumer<Config.TDFReaderConfig>>();
        options.add(Config.WithIgnoreKasAllowlist(true));
        if (keys != null) {
            options.add(Config.withAssertionVerificationKeys(keys));
        }
        @SuppressWarnings("unchecked")
        Consumer<Config.TDFReaderConfig>[] asArray = options.toArray(new Consumer[0]);
        return new TDF(new FakeServicesBuilder().setKas(KAS).build())
                .loadTDF(new SeekableInMemoryByteChannel(tdf), Config.newTDFReaderConfig(asArray));
    }

    private static void assertDecrypts(byte[] tdf, Config.AssertionVerificationKeys keys) throws IOException {
        var reader = load(tdf, keys);
        var out = new ByteArrayOutputStream();
        reader.readPayload(out);
        assertThat(out.toByteArray()).isEqualTo(PLAINTEXT);
    }

    private static void assertFails(byte[] tdf, Config.AssertionVerificationKeys keys, AssertionFailureReason reason,
            String id) {
        assertThatThrownBy(() -> load(tdf, keys))
                .isInstanceOfSatisfying(SDK.AssertionFailureException.class, e -> {
                    assertThat(e.getReason()).isEqualTo(reason);
                    assertThat(e.getAssertionId()).isEqualTo(id);
                    assertThat(e.getMessage()).contains("reason=" + reason.code()).contains("assertion")
                            .contains("tamper");
                    if (id != null) {
                        assertThat(e.getMessage()).contains("id: " + id);
                    }
                })
                .isInstanceOf(SDK.AssertionException.class);
    }

    private static Config.AssertionVerificationKeys perId(String id, AssertionConfig.AssertionKey key) {
        var keys = new Config.AssertionVerificationKeys();
        keys.keys.put(id, key);
        return keys;
    }

    private static Config.AssertionVerificationKeys defaultKey(AssertionConfig.AssertionKey key) {
        var keys = new Config.AssertionVerificationKeys();
        keys.defaultKey = key;
        return keys;
    }

    private static AssertionConfig.AssertionKey rs256(KeyPair keyPair) {
        return new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.RS256, keyPair.getPublic());
    }

    private static AssertionConfig.AssertionKey hs256(byte[] secret) {
        return new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.HS256, secret);
    }

    // ------------------------------------------------------------ manifest surgery

    private static JsonObject manifestOf(byte[] tdf) throws IOException {
        return JsonParser.parseString(new String(entry(tdf, TDFWriter.TDF_MANIFEST_FILE_NAME), StandardCharsets.UTF_8))
                .getAsJsonObject();
    }

    private static byte[] entry(byte[] tdf, String name) throws IOException {
        for (var entry : new ZipReader(new SeekableInMemoryByteChannel(tdf)).getEntries()) {
            if (entry.getName().equals(name)) {
                try (InputStream data = entry.getData()) {
                    return data.readAllBytes();
                }
            }
        }
        throw new IllegalArgumentException("no entry named " + name);
    }

    /** A copy of the TDF with its manifest JSON edited. */
    private static byte[] rewrite(byte[] tdf, Consumer<JsonObject> edit) throws IOException {
        var manifest = manifestOf(tdf);
        edit.accept(manifest);
        var out = new ByteArrayOutputStream();
        var writer = new TDFWriter(out);
        try (var payload = writer.payload()) {
            payload.write(entry(tdf, TDFWriter.TDF_PAYLOAD_FILE_NAME));
        }
        try (var manifestOut = writer.manifest()) {
            manifestOut.write(new Gson().toJson(manifest).getBytes(StandardCharsets.UTF_8));
        }
        writer.finish();
        return out.toByteArray();
    }

    private static JsonArray assertions(JsonObject manifest) {
        return manifest.getAsJsonArray("assertions");
    }

    private static byte[] aggregate(JsonObject manifest) {
        var aggregate = new ByteArrayOutputStream();
        for (var segment : manifest.getAsJsonObject("encryptionInformation").getAsJsonObject("integrityInformation")
                .getAsJsonArray("segments")) {
            aggregate.writeBytes(Base64.getDecoder().decode(segment.getAsJsonObject().get("hash").getAsString()));
        }
        return aggregate.toByteArray();
    }

    enum Embedded { NONE, JWK, X5C, BOTH }

    /** The wire form of an assertion, without its binding. */
    private static JsonObject wire(String id, String classification) {
        var statement = new JsonObject();
        statement.addProperty("format", "json+stanag5636");
        statement.addProperty("schema", "urn:nato:stanag:5636:A:1:elements:json");
        statement.addProperty("value", "{\"ocl\":{\"cls\":\"" + classification + "\"}}");
        var assertion = new JsonObject();
        assertion.addProperty("id", id);
        assertion.addProperty("type", "handling");
        assertion.addProperty("scope", "payload");
        assertion.addProperty("appliesToState", "unencrypted");
        assertion.add("statement", statement);
        return assertion;
    }

    /**
     * Binds {@code assertion} to {@code manifest}'s payload exactly as a writer would, signing
     * with {@code signer} (RS256) and embedding {@code embedded} in the JWS header.
     */
    private static JsonObject bind(JsonObject manifest, JsonObject assertion, KeyPair signer, KeyPair embedded,
            Embedded what) throws Exception {
        var header = new JWSHeader.Builder(JWSAlgorithm.RS256);
        if (what == Embedded.JWK || what == Embedded.BOTH) {
            header.jwk(new RSAKey.Builder((RSAPublicKey) embedded.getPublic()).build());
        }
        if (what == Embedded.X5C || what == Embedded.BOTH) {
            var certificate = TestUtil.createTestCertificate(embedded.getPublic(), embedded.getPrivate());
            header.x509CertChain(List.of(com.nimbusds.jose.util.Base64.encode(certificate.getEncoded())));
        }
        var jwt = new SignedJWT(header.build(), claims(manifest, assertion));
        jwt.sign(new RSASSASigner(signer.getPrivate()));
        return withBinding(assertion, jwt.serialize());
    }

    private static JsonObject bindHs256(JsonObject manifest, JsonObject assertion, byte[] secret,
            Consumer<JWSHeader.Builder> headerEdit) throws Exception {
        var header = new JWSHeader.Builder(JWSAlgorithm.HS256);
        headerEdit.accept(header);
        var jwt = new SignedJWT(header.build(), claims(manifest, assertion));
        jwt.sign(new MACSigner(secret));
        return withBinding(assertion, jwt.serialize());
    }

    private static JWTClaimsSet claims(JsonObject manifest, JsonObject assertion) throws Exception {
        String hash = Manifest.Assertion.computeAssertionHash(assertion.toString());
        byte[] aggregate = aggregate(manifest);
        byte[] hashBytes = Hex.decodeHex(hash);
        byte[] bound = new byte[aggregate.length + hashBytes.length];
        System.arraycopy(aggregate, 0, bound, 0, aggregate.length);
        System.arraycopy(hashBytes, 0, bound, aggregate.length, hashBytes.length);
        return new JWTClaimsSet.Builder()
                .claim("assertionHash", hash)
                .claim("assertionSig", Base64.getEncoder().encodeToString(bound))
                .build();
    }

    private static JsonObject withBinding(JsonObject assertion, String signature) {
        var bound = assertion.deepCopy();
        var binding = new JsonObject();
        binding.addProperty("method", "jws");
        binding.addProperty("signature", signature);
        bound.add("binding", binding);
        return bound;
    }

    // ---------------------------------------------------------------- controls

    @Test
    void theConfiguredSignerVerifiesPerIdAndAsTheDefault() throws Exception {
        var tdf = createTdf(assertionConfig(ID, issuerSigningKey()));
        assertDecrypts(tdf, perId(ID, rs256(issuer)));
        assertDecrypts(tdf, defaultKey(rs256(issuer)));
        // an RSA JWK is accepted as the configured key too
        assertDecrypts(tdf, perId(ID, new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.RS256,
                new RSAKey.Builder((RSAPublicKey) issuer.getPublic()).build())));
    }

    @Test
    void anUnkeyedAssertionVerifiesWithThePayloadKey() throws Exception {
        var tdf = createTdf(assertionConfig(ID, null));
        assertDecrypts(tdf, null);
        assertDecrypts(tdf, new Config.AssertionVerificationKeys());
        // a zero-value default key is the same as none
        assertDecrypts(tdf, defaultKey(new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.NotDefined, null)));
    }

    /** The Java writer may embed its key; that still verifies when the reader configured the same key. */
    @ParameterizedTest
    @EnumSource(value = Embedded.class, names = {"JWK", "X5C", "BOTH"})
    void javaWriterEmbeddedKeysVerifyWithThatKeyConfigured(Embedded embedded) throws Exception {
        var signingKey = issuerSigningKey();
        if (embedded == Embedded.JWK || embedded == Embedded.BOTH) {
            signingKey.withJwk(new RSAKey.Builder((RSAPublicKey) issuer.getPublic()).build());
        }
        if (embedded == Embedded.X5C || embedded == Embedded.BOTH) {
            var certificate = TestUtil.createTestCertificate(issuer.getPublic(), issuer.getPrivate());
            signingKey.withX5c(List.of(com.nimbusds.jose.util.Base64.encode(certificate.getEncoded())));
        }
        var tdf = createTdf(assertionConfig(ID, signingKey));
        assertDecrypts(tdf, perId(ID, rs256(issuer)));
        assertDecrypts(tdf, defaultKey(rs256(issuer)));
        // the embedded key alone grants nothing
        assertFails(tdf, null, AssertionFailureReason.ALGORITHM_MISMATCH, ID);
        assertFails(tdf, defaultKey(rs256(unrelated)), AssertionFailureReason.SIGNER_NOT_PERMITTED, ID);
    }

    // ------------------------------------------------- embedded keys of other signers

    static Stream<Arguments> unrelatedSignerCases() {
        var arguments = new ArrayList<Arguments>();
        for (var embedded : List.of(Embedded.JWK, Embedded.X5C, Embedded.BOTH)) {
            for (var replace : List.of(false, true)) {
                for (var asDefault : List.of(false, true)) {
                    arguments.add(Arguments.of(embedded, replace, asDefault));
                }
            }
        }
        return arguments.stream();
    }

    /**
     * A binding signed by an unrelated key, with that key embedded as jwk, x5c or both, fails
     * against the configured key, per ID or default, whether its assertion is added alongside
     * the original or replaces it.
     */
    @ParameterizedTest(name = "embedded={0} replace={1} defaultKey={2}")
    @MethodSource("unrelatedSignerCases")
    void anUnrelatedSignerWithAnEmbeddedKeyFailsAgainstTheConfiguredKey(Embedded embedded, boolean replace,
            boolean asDefault)
            throws Exception {
        var original = createTdf(assertionConfig(ID, issuerSigningKey()));
        var keys = asDefault ? defaultKey(rs256(issuer)) : perId(ID, rs256(issuer));
        assertDecrypts(original, keys);

        var edited = rewrite(original, manifest -> {
            try {
                var other = bind(manifest, wire(ID, "UNCLASSIFIED"), unrelated, unrelated, embedded);
                if (replace) {
                    assertions(manifest).set(0, other);
                } else {
                    assertions(manifest).add(other);
                }
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
        assertFails(edited, keys, AssertionFailureReason.SIGNER_NOT_PERMITTED, ID);
    }

    @Test
    void anAssertionUnderAnotherIdGetsTheDefaultOrPayloadKeyNotItsHeaderKey() throws Exception {
        var original = createTdf(assertionConfig(ID, issuerSigningKey()));
        var edited = rewrite(original, manifest -> {
            try {
                assertions(manifest).add(bind(manifest, wire("other", "UNCLASSIFIED"), unrelated, unrelated, Embedded.JWK));
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
        // with a default pin, the new id gets the default key
        assertDecrypts(original, defaultKey(rs256(issuer)));
        assertFails(edited, defaultKey(rs256(issuer)), AssertionFailureReason.SIGNER_NOT_PERMITTED, "other");
        // with only a per-ID pin, the new id gets the payload key, never the header's key
        assertDecrypts(original, perId(ID, rs256(issuer)));
        assertFails(edited, perId(ID, rs256(issuer)), AssertionFailureReason.ALGORITHM_MISMATCH, "other");
    }

    @Test
    void bindingsFromOtherKeysFailWhenThePayloadKeyIsSelected() throws Exception {
        var original = createTdf(assertionConfig(ID, null));
        assertDecrypts(original, null);

        for (var embedded : List.of(Embedded.JWK, Embedded.X5C)) {
            var rsaBinding = rewrite(original, manifest -> {
                try {
                    assertions(manifest).set(0, bind(manifest, wire(ID, "UNCLASSIFIED"), unrelated, unrelated, embedded));
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            });
            assertFails(rsaBinding, null, AssertionFailureReason.ALGORITHM_MISMATCH, ID);
        }

        byte[] otherSecret = AesGcm.generateKey();
        var hmacWithJwk = rewrite(original, manifest -> {
            try {
                assertions(manifest).set(0, bindHs256(manifest, wire(ID, "UNCLASSIFIED"), otherSecret,
                        header -> header.jwk(new RSAKey.Builder((RSAPublicKey) unrelated.getPublic()).build())));
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
        assertFails(hmacWithJwk, null, AssertionFailureReason.INVALID_EMBEDDED_KEY, ID);

        var hmacWithoutHeaderKey = rewrite(original, manifest -> {
            try {
                assertions(manifest).set(0, bindHs256(manifest, wire(ID, "UNCLASSIFIED"), otherSecret, header -> { }));
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
        assertFails(hmacWithoutHeaderKey, null, AssertionFailureReason.SIGNATURE_INVALID, ID);
    }

    @Test
    void theSelectedKeysOwnJwkSignedByAnotherKeyFailsTheSignature() throws Exception {
        var original = createTdf(assertionConfig(ID, issuerSigningKey()));
        var edited = rewrite(original, manifest -> {
            try {
                assertions(manifest).set(0, bind(manifest, wire(ID, "UNCLASSIFIED"), unrelated, issuer, Embedded.BOTH));
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
        assertFails(edited, perId(ID, rs256(issuer)), AssertionFailureReason.SIGNATURE_INVALID, ID);
    }

    @Test
    void contradictoryEmbeddedKeysAreRejected() throws Exception {
        var original = createTdf(assertionConfig(ID, issuerSigningKey()));
        var edited = rewrite(original, manifest -> {
            try {
                var assertion = wire(ID, "SECRET");
                var certificate = TestUtil.createTestCertificate(unrelated.getPublic(), unrelated.getPrivate());
                var header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .jwk(new RSAKey.Builder((RSAPublicKey) issuer.getPublic()).build())
                        .x509CertChain(List.of(com.nimbusds.jose.util.Base64.encode(certificate.getEncoded())));
                var jwt = new SignedJWT(header.build(), claims(manifest, assertion));
                jwt.sign(new RSASSASigner(issuer.getPrivate()));
                assertions(manifest).set(0, withBinding(assertion, jwt.serialize()));
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
        assertFails(edited, perId(ID, rs256(issuer)), AssertionFailureReason.INVALID_EMBEDDED_KEY, ID);
    }

    // ------------------------------------------------------------ selection order

    @Test
    void aFailedPerIdKeyDoesNotFallBackToTheDefaultKey() throws Exception {
        var tdf = createTdf(assertionConfig(ID, issuerSigningKey()));
        var keys = perId(ID, rs256(unrelated));
        keys.defaultKey = rs256(issuer);
        assertFails(tdf, keys, AssertionFailureReason.SIGNATURE_INVALID, ID);
        // control: the same default verifies when there is no per-ID entry
        assertDecrypts(tdf, defaultKey(rs256(issuer)));
    }

    @Test
    void aFailedConfiguredKeyDoesNotFallBackToThePayloadKey() throws Exception {
        var tdf = createTdf(assertionConfig(ID, null));
        assertDecrypts(tdf, null);
        assertFails(tdf, perId(ID, hs256(AesGcm.generateKey())), AssertionFailureReason.SIGNATURE_INVALID, ID);
        assertFails(tdf, defaultKey(hs256(AesGcm.generateKey())), AssertionFailureReason.SIGNATURE_INVALID, ID);
        assertFails(tdf, defaultKey(rs256(issuer)), AssertionFailureReason.ALGORITHM_MISMATCH, ID);
    }

    @Test
    void perIdKeysMatchTheExactId() throws Exception {
        var tdf = createTdf(assertionConfig(ID, issuerSigningKey()));
        // a differently cased entry does not apply, so the payload key is selected
        assertFails(tdf, perId("Assertion1", rs256(issuer)), AssertionFailureReason.ALGORITHM_MISMATCH, ID);
        assertDecrypts(tdf, perId(ID, rs256(issuer)));
    }

    @Test
    void theAlgorithmComesFromTheConfiguredKey() throws Exception {
        var tdf = createTdf(assertionConfig(ID, issuerSigningKey()));
        assertFails(tdf, perId(ID, hs256(AesGcm.generateKey())), AssertionFailureReason.ALGORITHM_MISMATCH, ID);
    }

    static Stream<Arguments> invalidConfiguredKeys() {
        var rsaPublic = CryptoUtils.generateRSAKeypair().getPublic();
        return Stream.of(
                Arguments.of("empty per-ID entry", perId(ID, null)),
                Arguments.of("RS256 with a secret", perId(ID,
                        new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.RS256, AesGcm.generateKey()))),
                Arguments.of("HS256 with public-key material", perId(ID,
                        new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.HS256, rsaPublic))),
                Arguments.of("HS256 with an empty secret", perId(ID, hs256(new byte[0]))),
                Arguments.of("HS256 secret shorter than 256 bits", perId(ID, hs256(new byte[16]))),
                Arguments.of("no algorithm", perId(ID,
                        new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.NotDefined, rsaPublic))),
                Arguments.of("default key with a key but no algorithm", defaultKey(
                        new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.NotDefined, rsaPublic))),
                Arguments.of("default key with an algorithm but no key", defaultKey(
                        new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.RS256, null))));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("invalidConfiguredKeys")
    void anInvalidConfiguredKeyIsAConfigurationError(String name, Config.AssertionVerificationKeys keys)
            throws Exception {
        // signed with the payload key, which would verify if the reader fell through to it
        var tdf = createTdf(assertionConfig(ID, null));
        assertDecrypts(tdf, null);
        assertFails(tdf, keys, AssertionFailureReason.CONFIGURATION_ERROR, ID);
    }

    // --------------------------------------------------------- hash as received

    @Test
    void unmodelledMembersAreAuthenticated() throws Exception {
        var original = createTdf(assertionConfig(ID, issuerSigningKey()));
        var signed = rewrite(original, manifest -> {
            try {
                var assertion = wire(ID, "SECRET");
                assertion.add("extensions", JsonParser.parseString("{\"releasableTo\":[\"USA\"]}"));
                assertion.getAsJsonObject("statement").addProperty("hash", "part of the statement");
                assertions(manifest).set(0, bind(manifest, assertion, issuer, issuer, Embedded.NONE));
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
        assertDecrypts(signed, perId(ID, rs256(issuer)));

        var tampered = rewrite(signed, manifest -> assertions(manifest).get(0).getAsJsonObject()
                .getAsJsonObject("extensions").getAsJsonArray("releasableTo").add("XXX"));
        assertFails(tampered, perId(ID, rs256(issuer)), AssertionFailureReason.BINDING_MISMATCH, ID);

        var nestedTamper = rewrite(signed, manifest -> assertions(manifest).get(0).getAsJsonObject()
                .getAsJsonObject("statement").addProperty("hash", "changed"));
        assertFails(nestedTamper, perId(ID, rs256(issuer)), AssertionFailureReason.BINDING_MISMATCH, ID);

        var added = rewrite(original, manifest ->
                assertions(manifest).get(0).getAsJsonObject().addProperty("note", "added after signing"));
        assertFails(added, perId(ID, rs256(issuer)), AssertionFailureReason.BINDING_MISMATCH, ID);
    }

    @Test
    void anObjectValuedStatementIsHashedAsAnObject() throws Exception {
        var original = createTdf(assertionConfig(ID, issuerSigningKey()));
        var acp240 = AssertionHashTest.acp240Assertion();
        acp240.addProperty("id", ID);
        var signed = rewrite(original, manifest -> {
            try {
                assertions(manifest).set(0, bind(manifest, acp240, issuer, issuer, Embedded.NONE));
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
        var reader = load(signed, perId(ID, rs256(issuer)));
        var read = reader.getManifest().assertions.get(0);
        assertThat(AssertionJson.hash(read.received())).isEqualTo(Manifest.Assertion.computeAssertionHash(acp240.toString()));
        assertThat(read.received().getAsJsonObject("statement").get("value").isJsonObject()).isTrue();

        var changed = rewrite(signed, manifest -> assertions(manifest).get(0).getAsJsonObject()
                .getAsJsonObject("statement").getAsJsonObject("value").getAsJsonObject("ocl")
                .addProperty("cls", "UNCLASSIFIED"));
        assertFails(changed, perId(ID, rs256(issuer)), AssertionFailureReason.BINDING_MISMATCH, ID);
    }

    // ----------------------------------------------------- ids and binding forms

    @Test
    void anInvalidIdFailsVerificationButNotParsing() throws Exception {
        var original = createTdf(assertionConfig(ID, null));
        for (JsonElement badId : List.of(new com.google.gson.JsonPrimitive(5), new com.google.gson.JsonPrimitive(""))) {
            var edited = rewrite(original, manifest -> assertions(manifest).get(0).getAsJsonObject().add("id", badId));
            assertFails(edited, null, AssertionFailureReason.INVALID_ID, null);
            var disabled = new TDF(new FakeServicesBuilder().setKas(KAS).build()).loadTDF(
                    new SeekableInMemoryByteChannel(edited),
                    Config.newTDFReaderConfig(Config.WithIgnoreKasAllowlist(true),
                            Config.withDisableAssertionVerification(true)));
            // the typed view never coerces a non-string id
            assertThat(disabled.getManifest().assertions.get(0).id).isEqualTo(badId.getAsJsonPrimitive().isString() ? "" : null);
        }
        var missing = rewrite(original, manifest -> assertions(manifest).get(0).getAsJsonObject().remove("id"));
        assertFails(missing, null, AssertionFailureReason.INVALID_ID, null);
    }

    @Test
    void bindingFormsFollowTheSpec() throws Exception {
        var original = createTdf(assertionConfig(ID, issuerSigningKey()));
        var keys = perId(ID, rs256(issuer));

        var upperCase = rewrite(original, manifest -> binding(manifest).addProperty("method", "JWS"));
        assertDecrypts(upperCase, keys);
        var noMethod = rewrite(original, manifest -> binding(manifest).remove("method"));
        assertDecrypts(noMethod, keys);

        assertFails(rewrite(original, manifest -> binding(manifest).addProperty("method", "jwt")), keys,
                AssertionFailureReason.UNSUPPORTED_BINDING, ID);
        assertFails(rewrite(original, manifest -> {
            var binding = binding(manifest);
            binding.remove("signature");
            binding.addProperty("bdo", "PGJkbz4=");
        }), keys, AssertionFailureReason.UNSUPPORTED_BINDING, ID);
        assertFails(rewrite(original, manifest -> binding(manifest).addProperty("bdo", "PGJkbz4=")), keys,
                AssertionFailureReason.INVALID_BINDING, ID);
        assertFails(rewrite(original, manifest -> binding(manifest).remove("signature")), keys,
                AssertionFailureReason.INVALID_BINDING, ID);
        assertFails(rewrite(original, manifest -> assertions(manifest).get(0).getAsJsonObject().remove("binding")),
                keys, AssertionFailureReason.INVALID_BINDING, ID);
        assertFails(rewrite(original, manifest -> assertions(manifest).get(0).getAsJsonObject()
                .addProperty("binding", "a.b.c")), keys, AssertionFailureReason.INVALID_BINDING, ID);
        assertFails(rewrite(original, manifest -> binding(manifest).addProperty("signature", "a.b")), keys,
                AssertionFailureReason.INVALID_BINDING, ID);
    }

    private static JsonObject binding(JsonObject manifest) {
        return assertions(manifest).get(0).getAsJsonObject().getAsJsonObject("binding");
    }

    @Test
    void verifyingLeavesTheParsedManifestUntouched() throws Exception {
        var tdf = createTdf(assertionConfig(ID, issuerSigningKey()));
        var reader = load(tdf, perId(ID, rs256(issuer)));
        var assertion = reader.getManifest().assertions.get(0);
        assertThat(assertion.binding).isNotNull();
        assertThat(assertion.binding.method).isEqualTo("jws");
        assertThat(assertion.binding.signature).isNotEmpty();
    }

    @Test
    void verifyChecksTheBindingWithExactlyTheGivenKey() throws Exception {
        var tdf = createTdf(assertionConfig(ID, issuerSigningKey().withJwk(
                new RSAKey.Builder((RSAPublicKey) issuer.getPublic()).build())));
        var assertion = SDK.readManifest(new SeekableInMemoryByteChannel(tdf)).assertions.get(0);

        var claims = assertion.verify(rs256(issuer));
        assertThat(claims.getAssertionHash()).isEqualTo(assertion.hash());

        assertThatThrownBy(() -> assertion.verify(rs256(unrelated)))
                .isInstanceOfSatisfying(SDK.AssertionFailureException.class,
                        e -> assertThat(e.getReason()).isEqualTo(AssertionFailureReason.SIGNER_NOT_PERMITTED));
        assertThatThrownBy(() -> assertion.verify(null))
                .isInstanceOfSatisfying(SDK.AssertionFailureException.class,
                        e -> assertThat(e.getReason()).isEqualTo(AssertionFailureReason.CONFIGURATION_ERROR));
        // and has no side effects
        assertThat(assertion.binding).isNotNull();

        // verify() and hash() read the same form: after a typed edit, the signed claims no
        // longer match the hash, and a changed binding is the binding checked
        assertion.statement.value = "changed";
        assertThat(assertion.verify(rs256(issuer)).getAssertionHash()).isNotEqualTo(assertion.hash());
        assertion.binding.signature = "not.a.jws.binding";
        assertThatThrownBy(() -> assertion.verify(rs256(issuer)))
                .isInstanceOfSatisfying(SDK.AssertionFailureException.class,
                        e -> assertThat(e.getReason()).isEqualTo(AssertionFailureReason.INVALID_BINDING));
    }
}
