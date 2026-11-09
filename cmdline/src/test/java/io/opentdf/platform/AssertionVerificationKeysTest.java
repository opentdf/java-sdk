package io.opentdf.platform;

import com.google.gson.JsonObject;
import io.opentdf.platform.sdk.AssertionConfig;
import io.opentdf.platform.sdk.Config;
import io.opentdf.platform.sdk.CryptoUtils;
import io.opentdf.platform.sdk.Manifest;
import io.opentdf.platform.sdk.SDKException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The decrypt command's {@code --with-assertion-verification-keys} file: per-ID keys and the
 * default key are both converted to SDK key material, so a default key works from the CLI.
 */
class AssertionVerificationKeysTest {

    private static final String HS256_SECRET = Base64.getEncoder().encodeToString(new byte[32]).replace('A', 'k');

    private static JsonObject key(String alg, String key) {
        var json = new JsonObject();
        json.addProperty("alg", alg);
        json.addProperty("key", key);
        return json;
    }

    private static String keysFile(JsonObject perId, JsonObject defaultKey) {
        var json = new JsonObject();
        if (perId != null) {
            json.add("keys", perId);
        }
        if (defaultKey != null) {
            json.add("defaultKey", defaultKey);
        }
        return json.toString();
    }

    /** An assertion signed with {@code signingKey}, the way the SDK writer signs it. */
    private static Manifest.Assertion signedAssertion(AssertionConfig.AssertionKey signingKey) throws Exception {
        var assertion = new Manifest.Assertion();
        assertion.id = "assertion1";
        assertion.type = "handling";
        assertion.scope = "payload";
        assertion.statement = new AssertionConfig.Statement();
        assertion.statement.format = "string";
        assertion.statement.value = "SECRET";
        assertion.sign(new Manifest.Assertion.HashValues(assertion.hash(), "c2ln"), signingKey);
        return assertion;
    }

    @Test
    void anHs256DefaultKeyIsTheUtf8BytesOfItsString() throws Exception {
        var keys = Command.parseAssertionVerificationKeys(keysFile(null, key("HS256", HS256_SECRET)));
        assertThat(keys.keys).isEmpty();
        assertThat(keys.defaultKey.alg).isEqualTo(AssertionConfig.AssertionKeyAlg.HS256);
        assertThat(keys.defaultKey.key).isEqualTo(HS256_SECRET.getBytes(StandardCharsets.UTF_8));

        var assertion = signedAssertion(new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.HS256,
                HS256_SECRET.getBytes(StandardCharsets.UTF_8)));
        assertThat(assertion.verify(keys.defaultKey).getAssertionHash()).isEqualTo(assertion.hash());
    }

    @Test
    void anRs256DefaultKeyIsAPemPublicKey() throws Exception {
        KeyPair signer = CryptoUtils.generateRSAKeypair();
        var keys = Command.parseAssertionVerificationKeys(
                keysFile(null, key("RS256", CryptoUtils.getPublicKeyPEM(signer.getPublic()))));
        assertThat(keys.defaultKey.key).isInstanceOf(RSAPublicKey.class).isEqualTo(signer.getPublic());

        var assertion = signedAssertion(
                new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.RS256, signer.getPrivate()));
        assertThat(assertion.verify(keys.defaultKey).getAssertionHash()).isEqualTo(assertion.hash());

        // and an unrelated default does not verify it
        var other = Command.parseAssertionVerificationKeys(keysFile(null,
                key("RS256", CryptoUtils.getPublicKeyPEM(CryptoUtils.generateRSAKeypair().getPublic()))));
        assertThatThrownBy(() -> assertion.verify(other.defaultKey)).isInstanceOf(SDKException.class);
    }

    @Test
    void perIdKeysAndTheDefaultAreReadTogetherFromAFile(@TempDir Path tempDir) throws Exception {
        KeyPair signer = CryptoUtils.generateRSAKeypair();
        var perId = new JsonObject();
        perId.add("assertion1", key("RS256", CryptoUtils.getPublicKeyPEM(signer.getPublic())));
        Path file = Files.writeString(tempDir.resolve("keys.json"), keysFile(perId, key("HS256", HS256_SECRET)));

        Config.AssertionVerificationKeys keys = Command.parseAssertionVerificationKeys(file.toString());
        assertThat(keys.keys.get("assertion1").key).isEqualTo(signer.getPublic());
        assertThat(keys.defaultKey.key).isEqualTo(HS256_SECRET.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void theDefaultKeyMayBeSpelledDefaultKey() {
        var json = new JsonObject();
        json.add("DefaultKey", key("HS256", HS256_SECRET));
        var keys = Command.parseAssertionVerificationKeys(json.toString());
        assertThat(keys.defaultKey.key).isEqualTo(HS256_SECRET.getBytes(StandardCharsets.UTF_8));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            // an alg Gson would read as null, which must not make the key absent
            "{'defaultKey':{'alg':'rs256','pem':'x'}}",
            "{'defaultKey':{'alg':'ES256'}}",
            "{'defaultKey':{'alg':'NotDefined','key':'x'}}",
            "{'defaultKey':{'alg':5,'key':'x'}}",
            "{'defaultKey':{'key':'x'}}",
            "{'defaultKey':{'pem':'x'}}",
            "{'keys':{'a':{'alg':'RS512','key':'x'}}}",
            "{'keys':{'a':{'key':'x'}}}",
            "{'keys':{'a':'x'}}",
            "{'keys':['x']}",
            "{'defaultKey':'x'}",
            // unknown top-level members, such as a misspelled default key
            "{'default_key':{'alg':'HS256','key':'x'}}",
            "{'keys':{},'extra':1}",
            "{'defaultKey':{'alg':'HS256','key':'kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk'},"
                    + "'DefaultKey':{'alg':'HS256','key':'kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk'}}",
    })
    void keysThatCannotBeUsedAsGivenAreConfigurationErrors(String singleQuoted) {
        assertThatThrownBy(() -> Command.parseAssertionVerificationKeys(singleQuoted.replace('\'', '"')))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("reason=configuration-error");
    }

    @Test
    void pemTextIsNeverAnHs256Secret() {
        String pem = CryptoUtils.getPublicKeyPEM(CryptoUtils.generateRSAKeypair().getPublic());
        assertThatThrownBy(() -> Command.parseAssertionVerificationKeys(keysFile(null, key("HS256", pem))))
                .hasMessageContaining("reason=configuration-error")
                .hasMessageContaining("PEM");
    }

    @ParameterizedTest
    @ValueSource(strings = {"{}", "{'defaultKey':null}", "{'defaultKey':{}}", "{'keys':null}", "{'keys':{}}"})
    void noDefaultKeyMeansNone(String singleQuoted) {
        var keys = Command.parseAssertionVerificationKeys(singleQuoted.replace('\'', '"'));
        assertThat(keys.defaultKey).isNull();
        assertThat(keys.keys).isEmpty();
    }

    @Test
    void anUnreadableKeyIsAConfigurationError() {
        assertThatThrownBy(() -> Command.parseAssertionVerificationKeys(keysFile(null, key("RS256", "not a pem"))))
                .hasMessageContaining("reason=configuration-error")
                .hasMessageContaining("default key");
    }

    @Test
    void anEmptyPerIdEntryIsLeftForTheSdkToReject() throws Exception {
        var keys = Command.parseAssertionVerificationKeys("{\"keys\":{\"assertion1\":null,\"assertion2\":{}}}");
        assertThat(keys.keys).containsKeys("assertion1", "assertion2");
        for (var entry : keys.keys.values()) {
            assertThat(entry).isNotNull();
            var assertion = signedAssertion(new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.HS256,
                    HS256_SECRET.getBytes(StandardCharsets.UTF_8)));
            assertThatThrownBy(() -> assertion.verify(entry))
                    .isInstanceOf(SDKException.class);
        }
    }
}
