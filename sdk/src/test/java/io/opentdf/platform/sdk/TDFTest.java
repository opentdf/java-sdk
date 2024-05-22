package io.opentdf.platform.sdk;

import org.apache.commons.io.output.ByteArrayOutputStream;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

public class TDFTest {
    @Test
    void testSimpleTDFEncryptAndDecrypt() throws Exception {
        Config.KASInfo kasInfo = new Config.KASInfo();
        kasInfo.URL = "http://127.0.0.1:8080/kas";
        kasInfo.PublicKey = "-----BEGIN PUBLIC KEY-----\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArvKYimFpxEp58ZGTgiaP\n" +
                "RYEzrikTZ3GP0KhWIYrQFAbWdE0qvSS+8LxcUDQoisFk1ux1CO9iuUlyZdKeGsbz\n" +
                "sTmJjdk4nHoH5f/BiLzTEJemDIjXPV5vYcY++4QKhFbZf/XLLZ2hSzAuXz5ZOCel\n" +
                "A/KZs+Zb19Vlra5DCDJ43mqdoqFIDS4cl8mtuRDC5Uw3x1S52tnO/TKPDGj32aVS\n" +
                "GBKh0CWGAXWRmphzGj7kFpkAxT1b827MrQMYxkn4w2WB8B/bGKz0+dWyqnnzGYAS\n" +
                "hVJ0rIiNE8dDWzQCRBfivLemXhX8UFICyoS5i0IwenFvTr6T85EvMxK3aSAlGya3\n" +
                "3wIDAQAB\n" +
                "-----END PUBLIC KEY-----";;

                // TODO: SDK should kas public key in cert format.
//"""
//-----BEGIN CERTIFICATE-----
//MIICmDCCAYACCQC3BCaSANRhYzANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDDANr
//YXMwHhcNMjEwOTE1MTQxMTQ4WhcNMjIwOTE1MTQxMTQ4WjAOMQwwCgYDVQQDDANr
//YXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDOpiotrvV2i5h6clHM
//zDGgh3h/kMa0LoGx2OkDPd8jogycUh7pgE5GNiN2lpSmFkjxwYMXnyrwr9ExyczB
//WJ7sRGDCDaQg5fjVUIloZ8FJVbn+sEcfQ9iX6vmI9/S++oGK79QM3V8M8cp41r/T
//1YVmuzUHE1say/TLHGhjtGkxHDF8qFy6Z2rYFTCVJQHNqGmwNVGd0qG7gim86Haw
//u/CMYj4jG9oITlj8rJtQOaJ6ZqemQVoNmb3j1LkyeUKzRIt+86aoBiz+T3TfOEvX
//F6xgBj3XoiOhPYK+abFPYcrArvb6oubT8NjjQoj3j0sXWUnIIMg+e4f+XNVU54Zz
//DaLZAgMBAAEwDQYJKoZIhvcNAQELBQADggEBABewfZOJ4/KNRE8IQ5TsW/AVn7C1
//l5ty6tUUBSVi8/df7WYts0bHEdQh9yl9agEU5i4rj43y8vMVZNzSeHcurtV/+C0j
//fbkHQHeiQ1xn7cq3Sbh4UVRyuu4C5PklEH4AN6gxmgXC3kT15uWw8I4nm/plzYLs
//I099IoRfC5djHUYYLMU/VkOIHuPC3sb7J65pSN26eR8bTMVNagk187V/xNwUuvkf
//+NUxDO615/5BwQKnAu5xiIVagYnDZqKCOtYS5qhxF33Nlnwlm7hH8iVZ1RI+n52l
//wVyElqp317Ksz+GtTIc+DE6oryxK3tZd4hrj9fXT4KiJvQ4pcRjpePgH7B8=
//-----END CERTIFICATE-----
//""";


        Config.TDFConfig config = Config.newTDFConfig(Config.withKasInformation(kasInfo));

        String plainText = "text";
        InputStream plainTextInputStream = new ByteArrayInputStream(plainText.getBytes());
        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();

        TDF tdf = new TDF();
        tdf.createTDF(plainTextInputStream, plainText.length(), tdfOutputStream, config);
    }
}
