package io.opentdf.platform.sdk;

import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.apache.commons.io.output.ByteArrayOutputStream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;

public class TDFTest {

    private static SDK.KAS kas = new SDK.KAS() {
        @Override
        public String getPublicKey(Config.KASInfo kasInfo) {
            int index = Integer.parseInt(kasInfo.URL);

            return "-----BEGIN PUBLIC KEY-----\r\n" +
                Base64.getMimeEncoder().encodeToString(keypairs.get(index).getPublic().getEncoded()) +
                "\r\n-----END PUBLIC KEY-----";
        }

        @Override
        public byte[] unwrap(Config.KASInfo kasInfo, String policy, byte[] wrappedKey) {
            int index = Integer.parseInt(kasInfo.URL);
            var decryptor = new AsymDecryption(keypairs.get(index).getPrivate());
            try {
                return decryptor.decrypt(wrappedKey);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    };

    private static ArrayList<KeyPair> keypairs = new ArrayList<>();

    @BeforeAll
    static void createKeypairs() throws NoSuchAlgorithmException {
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

        Config.TDFConfig config = Config.newTDFConfig(Config.withKasInformation(kasInfos.toArray(new Config.KASInfo[0])));

        String plainText = "text";
        InputStream plainTextInputStream = new ByteArrayInputStream(plainText.getBytes());
        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();

        TDF tdf = new TDF();
        tdf.createTDF(plainTextInputStream, plainText.length(), tdfOutputStream, config, kas);

        var unwrappedData = new java.io.ByteArrayOutputStream();
        tdf.loadTDF(new SeekableInMemoryByteChannel(tdfOutputStream.toByteArray()), unwrappedData, kas);
    }
}
