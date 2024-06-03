package io.opentdf.platform.sdk;

import org.apache.commons.io.output.ByteArrayOutputStream;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Base64;


public class NanoTDFTest {

    public static final String kasPublicKey = """
                -----BEGIN PUBLIC KEY-----
                MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC4Wmdb7smRiIeA/Zkua2TNj9kySE
                8Q2MaJ0kQX9GFePqi5KNDVnjBxQrkHXSTGB7Z/SrRny9vxgo86FT+1aXMQ==
                -----END PUBLIC KEY-----
                """;

    public static final String kasPrivateKey = """
                -----BEGIN PRIVATE KEY-----
                MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg2Wgo3sPikn/fj9uU
                /cU+F4I2rRyOit9/s3fNjHVLxgugCgYIKoZIzj0DAQehRANCAAQLhaZ1vuyZGIh4
                D9mS5rZM2P2TJITxDYxonSRBf0YV4+qLko0NWeMHFCuQddJMYHtn9KtGfL2/GCjz
                oVP7Vpcx
                -----END PRIVATE KEY-----
                """;

    private static SDK.KAS kas = new SDK.KAS() {
        @Override
        public String getPublicKey(Config.KASInfo kasInfo) {
            return kasPublicKey;
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

    @Test
    void encryptionAndDecryptionWithValidKey() throws Exception {
        var kasInfos = new ArrayList<>();
        var kasInfo = new Config.KASInfo();
        kasInfo.URL = "https://opentdf.io";
        kasInfo.PublicKey = null;
        kasInfos.add(kasInfo);

        Config.NanoTDFConfig config = Config.newNanoTDFConfig(
                Config.withNanoKasInformation(kasInfos.toArray(new Config.KASInfo[0]))
        );

        String plainText = "Virtru!!";
        ByteBuffer byteBuffer = ByteBuffer.wrap(plainText.getBytes());
        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();

        NanoTDF nanoTDF = new NanoTDF();
        nanoTDF.createNanoTDF(byteBuffer, tdfOutputStream, config, kas);
    }
}
