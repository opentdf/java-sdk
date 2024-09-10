package io.opentdf.platform.sdk;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

class AsymDecryptionTest {

    @Test
    void decryptionWithValidPrivateKey() throws Exception {
        String privateKeyInPem = "-----BEGIN PRIVATE KEY-----\n" +
                "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCu8piKYWnESnnx\n" +
                "kZOCJo9FgTOuKRNncY/QqFYhitAUBtZ0TSq9JL7wvFxQNCiKwWTW7HUI72K5SXJl\n" +
                "0p4axvOxOYmN2Ticegfl/8GIvNMQl6YMiNc9Xm9hxj77hAqEVtl/9cstnaFLMC5f\n" +
                "Plk4J6UD8pmz5lvX1WWtrkMIMnjeap2ioUgNLhyXya25EMLlTDfHVLna2c79Mo8M\n" +
                "aPfZpVIYEqHQJYYBdZGamHMaPuQWmQDFPVvzbsytAxjGSfjDZYHwH9sYrPT51bKq\n" +
                "efMZgBKFUnSsiI0Tx0NbNAJEF+K8t6ZeFfxQUgLKhLmLQjB6cW9OvpPzkS8zErdp\n" +
                "ICUbJrffAgMBAAECggEAQqf36rGW5M0jjSDUPQCIEglaMX9A/2bLTsr0li8XfKnm\n" +
                "R8WnBQ3dGkgKPBzDXaq1yxWoudDLoqETTyxiRP2Ml/e+KyeaZDQykjVR/dFD8cx1\n" +
                "3cy9hYpXkb9A+/+hKi8VC6YQ1b57V/RxlqRgxf6E5u4mFd8tGx0ZcoU00Qi5+LOw\n" +
                "tfSKLPNg4OujraCmrq/bgNkNEiMwHK2AQTbr31uhygUiGTmdXVZu1FLqg7WPGZyZ\n" +
                "x/0U83x0dx6A890OFaebw7I84/tmyJYqutgkK3BhsvIHj1sr34PNdbAMACY/+vqu\n" +
                "r5H7+oCvILlo4pVQ760NBWxIvv6GQGIedH/18GuX4QKBgQDlXxMuyUnUPVXCZWgw\n" +
                "ckvaTXYpQY8om9L4tPeQpQWFhT7pVByQhxIKcmwpAvz5ZhTZUo3ERfuYgheoM6Ay\n" +
                "0AXeuSGagpYWT+rb2DusmDgZIn6wBaMdZX1tll4rNTPOb0rRpQasyJRd6Li9+C9G\n" +
                "A8cRxDKZfiaLSXi2xT45fZuFCQKBgQDDQgugZVGdbIMWJd5KfB7VQbjbkmt+6Q5r\n" +
                "pMY4NMXYCggG1DUuaNwC5Ptl2QE3Z98ZJnYhAvXW0IaD7OyjqOItA00Q4+v8nv/I\n" +
                "Bu5hCtIFHx+xCQtWL8IApjTckmen8YmFNBSgQHsCBR7oR51orgHu9HsPcTh5Jq5V\n" +
                "oBr67a43pwKBgQCIYTJvtCFgv6NZNaBwhdUSFNK4DxIGzDfxxvAYIfaZgDN62pct\n" +
                "XBJfAc/LxsoRpB+rZAmE9TN2Z4uXaDLNY6DJ3/vZ+eExnQ0A8J3yroNUdo0rLf7h\n" +
                "gLHGUgzl1flauhObeWrxm0WUXMZTtdit4Zsgti5702UplmLfEYJA/q1UuQKBgBbb\n" +
                "jHDia4N6SH43QKaHkTR11SYfJeZdcgq351x9EQwRYI8sGG2uaNMN60Ao/zN1PXC8\n" +
                "R+flaNIU5ypaeflOs+uBD2yCwgV4t4i7BvzlP2DKG/Olk2YrgRKCYn3PxcKrS+YE\n" +
                "CsYXxk6eOtgGSi8O77sBc8aDApFsLcxoScBGQrbRAoGANZKkKXpe7kNn05Td5JMY\n" +
                "QchqRD9x1z/8zyWSnwpRlfUG3RnRRqyv14gHK1sTaIcb6hTKkcUnoP6cBQZOR8wQ\n" +
                "b9jhi/YwGgMbC7wI11l70vJzf1ydKfI0JeGy51UP/8bCw8sAf67z/S7nwWZBUsrM\n" +
                "X3wz+2TeAgQK0jsLzrv0R8A=\n" +
                "-----END PRIVATE KEY-----\n";
        AsymDecryption asymDecryption = new AsymDecryption(privateKeyInPem);
        String plaintext = "Virtru, JavaSDK!";

        String str = "E/eLD2RiC+79RRyn8BqECVcvLThRGwmVQaaMffMf735n4VY40AX0DRINKj6DulI8KApM/R8J4BZLgGEsPMbkVdoPFSCZqaSnoINjNFXqIpAWOHG4MSyr2PPAy/H96DoXeKf1OlcE5LNWj8xY7Z25pxQjclmNyahQDSa7DrMkMBj8q5yDrB4uw239jy43CTQByNSHKDNpS5vMT1GXvGCQ9o44VKUtd16Yf0aI3HN5YoUqPHmgd4KwwO3ok0eiSc+TUopNTUgDyZB8oCojLnGm7F/JZIHPas/46D1cvSPt7XMuqnO2wzfSJiJcbsLFg0zBZf2GnVLQKhCPnDAf9AnobQ==";
        byte[] cipherText = Base64.getDecoder().decode(str);

        byte[] decryptedData = asymDecryption.decrypt(cipherText);
        String decryptedStr = new String(decryptedData, StandardCharsets.UTF_8);

        assertNotNull(decryptedData);
        assertEquals(plaintext, decryptedStr);
    }
}