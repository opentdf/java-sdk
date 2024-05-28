package io.opentdf.platform.sdk;

import org.apache.commons.compress.utils.Lists;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.apache.commons.io.output.ByteArrayOutputStream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

public class TDFTest {

    private static SDK.KAS kas = new SDK.KAS() {
        @Override
        public String getPublicKey(Config.KASInfo kasInfo) {
            int index = Integer.parseInt(kasInfo.URL);

            return CryptoUtils.getRSAPublicKeyPEM(keypairs.get(index).getPublic());
        }

        @Override
        public byte[] unwrap(Manifest.KeyAccess keyAccess, String policy) {
            int index = Integer.parseInt(keyAccess.url);
            var decryptor = new AsymDecryption(keypairs.get(index).getPrivate());
            var bytes = Base64.getDecoder().decode(keyAccess.wrappedKey);
            try {
                return decryptor.decrypt(bytes);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    };

    private static ArrayList<KeyPair> keypairs = new ArrayList<>();

    @BeforeAll
    static void createKeypairs() {
        for (int i = 0; i < 5; i++) {
            keypairs.add(CryptoUtils.generateRSAKeypair());
        }
    }
    @Test
    void testSimpleTDFEncryptAndDecrypt() throws Exception {
        var kasInfos = new ArrayList<>();
        for (int i = 0; i < keypairs.size(); i++) {
            var kasInfo = new Config.KASInfo();
            kasInfo.URL = Integer.toString(i);
            kasInfo.PublicKey = null;
            kasInfos.add(kasInfo);
        }

        Config.TDFConfig config = Config.newTDFConfig(
                Config.withKasInformation(kasInfos.toArray(new Config.KASInfo[0]))
        );

        String plainText = "this is extremely sensitive stuff!!!";
        InputStream plainTextInputStream = new ByteArrayInputStream(plainText.getBytes());
        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();

        TDF tdf = new TDF();
        tdf.createTDF(plainTextInputStream, plainText.length(), tdfOutputStream, config, kas);

        var unwrappedData = new java.io.ByteArrayOutputStream();
        tdf.loadTDF(new SeekableInMemoryByteChannel(tdfOutputStream.toByteArray()), unwrappedData, kas);

        assertThat(unwrappedData.toString(StandardCharsets.UTF_8))
                .isEqualTo(plainText);

    }
}
