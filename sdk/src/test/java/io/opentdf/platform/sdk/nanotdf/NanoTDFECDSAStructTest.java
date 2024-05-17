package io.opentdf.platform.sdk.nanotdf;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class NanoTDFECDSAStructTest {
    @Test
    void testECDSASigStruct() throws NanoTDFECDSAStruct.IncorrectNanoTDFECDSASignatureSize {
        int keySizeBytes = 32;
        byte[] l = {(byte) keySizeBytes};
        byte[] b = new byte[keySizeBytes];

        new Random().nextBytes(b);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        outputStream.writeBytes(l);
        new Random().nextBytes(b);
        byte[] rValue = Arrays.copyOf(b, b.length);
        outputStream.writeBytes(b);
        outputStream.writeBytes(l);
        new Random().nextBytes(b);
        byte[] sValue =  Arrays.copyOf(b, b.length);
        outputStream.writeBytes(b);

        NanoTDFECDSAStruct nanoTDFECDSAStruct = new NanoTDFECDSAStruct(outputStream.toByteArray(), keySizeBytes);
        assertArrayEquals(nanoTDFECDSAStruct.getrValue(), rValue);
        assertArrayEquals(nanoTDFECDSAStruct.getsValue(), sValue);
    }
}
