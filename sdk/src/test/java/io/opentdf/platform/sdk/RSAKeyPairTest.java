package io.opentdf.platform.sdk;

import com.nimbusds.jose.jwk.KeyUse;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import static io.opentdf.platform.sdk.RSAKeyPair.CIPHER_TRANSFORM;
import static org.assertj.core.api.Assertions.assertThat;

public class RSAKeyPairTest {
    @Test
    public void testEncryptingAndDecrypting() throws Exception {
        var keypair = new RSAKeyPair();

        var inData = "this is a secret message".getBytes(StandardCharsets.UTF_8);
        var encrypted = keypair.getAsymEncryption().encrypt(inData);
        var decrypted = keypair.getAsymDecryption().decrypt(encrypted);

        assertThat(decrypted).isEqualTo(inData);
    }

    @Test
    public void testGeneratingPEM() throws Exception {
        var keypair = new RSAKeyPair();
        var pem = keypair.publicKeyPEM();
        var pemLines = pem.split("([\\r\\n])+");
        assertThat(pemLines[0]).isEqualTo("-----BEGIN PUBLIC KEY-----");
        assertThat(pemLines[pemLines.length - 1]).isEqualTo("-----END PUBLIC KEY-----");
        var derLines = Arrays.copyOfRange(pemLines, 1, pemLines.length - 1);
        var der = String.join("", derLines);

        var spec = new X509EncodedKeySpec(Base64.getDecoder().decode(der));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        var publicKey = kf.generatePublic(spec);

        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        var plaintext = "more secret stuff".getBytes(StandardCharsets.UTF_8);
        var encrypted = cipher.doFinal(plaintext);
        var decrypted = keypair.getAsymDecryption().decrypt(encrypted);

        assertThat(decrypted).isEqualTo(plaintext);
    }

    @Test
    public void testGettingRSAJWK() {
        var keypair = new RSAKeyPair();
        var rsaKey = keypair.toRSAKey();
        assertThat(rsaKey.isPrivate()).isTrue();
        assertThat(rsaKey.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
    }

    @Test
    public void testGettingJWSSigner() {
        var keypair = new RSAKeyPair();
        var rsaKey = keypair.toRSAKey();
        assertThat(rsaKey.isPrivate()).isTrue();
        assertThat(rsaKey.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
    }
}
