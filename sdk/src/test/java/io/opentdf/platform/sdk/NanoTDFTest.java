package io.opentdf.platform.sdk;

import io.opentdf.platform.sdk.nanotdf.ECKeyPair;
import io.opentdf.platform.sdk.nanotdf.Header;
import io.opentdf.platform.sdk.nanotdf.NanoTDFType;
import java.nio.charset.StandardCharsets;
import org.apache.commons.io.output.ByteArrayOutputStream;
import org.junit.jupiter.api.Test;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Random;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;


public class NanoTDFTest {

    public static final String kasPublicKey = "-----BEGIN PUBLIC KEY-----\n" +
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC4Wmdb7smRiIeA/Zkua2TNj9kySE\n" +
            "8Q2MaJ0kQX9GFePqi5KNDVnjBxQrkHXSTGB7Z/SrRny9vxgo86FT+1aXMQ==\n" +
            "-----END PUBLIC KEY-----";

    public static final String kasPrivateKey = "-----BEGIN PRIVATE KEY-----\n" +
            "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg2Wgo3sPikn/fj9uU\n" +
            "/cU+F4I2rRyOit9/s3fNjHVLxgugCgYIKoZIzj0DAQehRANCAAQLhaZ1vuyZGIh4\n" +
            "D9mS5rZM2P2TJITxDYxonSRBf0YV4+qLko0NWeMHFCuQddJMYHtn9KtGfL2/GCjz\n" +
            "oVP7Vpcx\n" +
            "-----END PRIVATE KEY-----";

    private static final String KID = "r1";
    
    private static SDK.KAS kas = new SDK.KAS() {
        @Override
        public void close() throws Exception {
        }

        @Override
        public Config.KASInfo getPublicKey(Config.KASInfo kasInfo) {
            Config.KASInfo returnKI = new Config.KASInfo();
            returnKI.PublicKey = kasPublicKey;
            return returnKI;
        }

        @Override
        public String getECPublicKey(Config.KASInfo kasInfo, NanoTDFType.ECCurve curve) {
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

        @Override
        public byte[] unwrapNanoTDF(NanoTDFType.ECCurve curve, String header, String kasURL) {

            byte[] headerAsBytes = Base64.getDecoder().decode(header);
            Header nTDFHeader = new Header(ByteBuffer.wrap(headerAsBytes));
            byte[] ephemeralKey = nTDFHeader.getEphemeralKey();

            String publicKeyAsPem = ECKeyPair.publicKeyFromECPoint(ephemeralKey, nTDFHeader.getECCMode().getCurveName());

            // Generate symmetric key
            byte[] symmetricKey = ECKeyPair.computeECDHKey(ECKeyPair.publicKeyFromPem(publicKeyAsPem),
                    ECKeyPair.privateKeyFromPem(kasPrivateKey));

            // Generate HKDF key
            MessageDigest digest;
            try {
                digest = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                throw new SDKException("error creating SHA-256 message digest", e);
            }
            byte[] hashOfSalt = digest.digest(NanoTDF.MAGIC_NUMBER_AND_VERSION);
            byte[] key = ECKeyPair.calculateHKDF(hashOfSalt, symmetricKey);
            return key;
        }

        @Override
        public KASKeyCache getKeyCache(){
            return new KASKeyCache();
        }
    };

    private static ArrayList<KeyPair> keypairs = new ArrayList<>();

    @Test
    void encryptionAndDecryptionWithValidKey() throws Exception {
        var kasInfos = new ArrayList<>();
        var kasInfo = new Config.KASInfo();
        kasInfo.URL = "https://api.example.com/kas";
        kasInfo.PublicKey = null;
        kasInfo.KID = KID;
        kasInfos.add(kasInfo);

        Config.NanoTDFConfig config = Config.newNanoTDFConfig(
                Config.withNanoKasInformation(kasInfos.toArray(new Config.KASInfo[0])),
                Config.witDataAttributes("https://example.com/attr/Classification/value/S",
                        "https://example.com/attr/Classification/value/X")
        );

        String plainText = "Virtru!!";
        ByteBuffer byteBuffer = ByteBuffer.wrap(plainText.getBytes());
        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();

        NanoTDF nanoTDF = new NanoTDF();
        nanoTDF.createNanoTDF(byteBuffer, tdfOutputStream, config, kas);

        byte[] nanoTDFBytes = tdfOutputStream.toByteArray();
        ByteArrayOutputStream plainTextStream = new ByteArrayOutputStream();
        nanoTDF = new NanoTDF();
        nanoTDF.readNanoTDF(ByteBuffer.wrap(nanoTDFBytes), plainTextStream, kas);

        String out = new String(plainTextStream.toByteArray(), StandardCharsets.UTF_8);
        assertThat(out).isEqualTo(plainText);
        // KAS KID
        assertThat(new String(nanoTDFBytes, StandardCharsets.UTF_8)).contains(KID);
        

        int[] nanoTDFSize = { 0, 1, 100*1024, 1024*1024, 4*1024*1024, 12*1024*1024, 15*1024,1024, ((16 * 1024 * 1024) - 3 - 32) };
        for (int size: nanoTDFSize) {
            byte[] data = new byte[size];
            new Random().nextBytes(data);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

            NanoTDF nTDF = new NanoTDF();
            nTDF.createNanoTDF(ByteBuffer.wrap(data), outputStream, config, kas);

            byte[] nTDFBytes = outputStream.toByteArray();
            ByteArrayOutputStream dataStream = new ByteArrayOutputStream();
            nanoTDF.readNanoTDF(ByteBuffer.wrap(nTDFBytes), dataStream, kas);
            assertThat(dataStream.toByteArray()).isEqualTo(data);
        }
    }
}
