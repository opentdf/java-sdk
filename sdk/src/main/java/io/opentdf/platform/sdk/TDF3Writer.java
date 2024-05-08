package io.opentdf.platform.sdk;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class TDF3Writer {
    private ZipWriter archiveWriter;
    private static final String TDF_PAYLOAD_FILE_NAME = "0.payload";
    private static final String TDF_MANIFEST_FILE_NAME = "0.manifest.json";

    public TDF3Writer(String filePath) throws FileNotFoundException {
        OutputStream stream = new FileOutputStream(filePath);
        this.archiveWriter = new ZipWriter(stream);
    }

    public void setPayloadSize(long payloadSize) throws IOException {
        if (payloadSize >= 4L * 1024 * 1024 * 1024) { // if file size is greater than 4GB)
            this.archiveWriter.enableZip64();
        }

        this.archiveWriter.addHeader(TDF_PAYLOAD_FILE_NAME, payloadSize);
    }

    public void appendManifest(String manifest) throws IOException {
        this.archiveWriter.addHeader(TDF_MANIFEST_FILE_NAME, (long) manifest.length());
        this.archiveWriter.addData(manifest.getBytes());
    }

    public void appendPayload(byte[] data) throws IOException {
        this.archiveWriter.addData(data);
    }

    public void finish() throws IOException {
        this.archiveWriter.finish();
    }

    public static void main(String[] args) {
        try {
            TDF3Writer writer = new TDF3Writer("sample22.tdf");
            writer.setPayloadSize("Hello, world! Virtru".length());
            writer.appendPayload("Hello, world! Virtru".getBytes());
            String jsonString = "{" +
                    "\"encryptionInformation\": {" +
                    "\"integrityInformation\": {" +
                    "\"encryptedSegmentSizeDefault\": 1048604," +
                    "\"rootSignature\": {" +
                    "\"alg\": \"HS256\"," +
                    "\"sig\": \"ZjEwYWRjMzJkNzVhMmNkMzljYTU3ZDg3YTJjNjMyMGYwOTZkYjZhZDY4ZTE1Y2Y1MzRlNTdjNjBhNjdlNWUwMQ==\"" +
                    "}," +
                    "\"segmentHashAlg\": \"GMAC\"," +
                    "\"segmentSizeDefault\": 1048576," +
                    "\"segments\": [" +
                    "{" +
                    "\"encryptedSegmentSize\": 228," +
                    "\"hash\": \"YWRkNDhhZWM0Y2VhNmQwZjU5Y2ViOTc5MmFhYzdlOTI=\"," +
                    "\"segmentSize\": 200" +
                    "}" +
                    "]" +
                    "}," +
                    "\"keyAccess\": [" +
                    "{" +
                    "\"encryptedMetadata\": \"eyJjaXBoZXJ0ZXh0IjoidkwyOUVVb1IyOFpVNStiMzFDdE1iNFFVODF5dVhPTnM3SUtDYlZNcDloZkg3dCs2UFRPaG00VFAwbVRDc3R3UEFkeU1ucHltbk4rWWNON0hmbytDIiwiaXYiOiJ2TDI5RVVvUjI4WlU1K2IzIn0=\"," +
                    "\"policyBinding\": \"Zjk1Mjg2ZDljMzYwNGE5ZmU3YWE2M2UzOWRmMjA5MGU2OTJkYTZiYjExNjFkZmZjNTI2N2JkMWY5M2Y3MzIzZQ==\"," +
                    "\"protocol\": \"kas\"," +
                    "\"type\": \"wrapped\"," +
                    "\"url\": \"http://localhost:65432/api/kas\"," +
                    "\"wrappedKey\": \"ARu5wnJPNDaivQymXKOogyC2n11QP4Jf8ZYtrAcYQnUmE9hsjQD2R+48js5T1LkNLp5TzaRREF5sSk5/dhlBge/YXVcT42d5lNp0SecAF68dsso/aXq+G2sRJFVWdYKAtc32mr8KJiPisHtPlPFPM7u37lU0YX93lsqIxiUPn6qkxkD4cEozvA9UgB8YZ8alJtNACnpbOUebJeRLkHbxXM7DzW4gur/lu88lRUtCdaHNBeSOTCgWi2oqTU70asyoFQVVD7R80xKblam5k/B3PKhCkerZkDwyy5D4eODbbqKpGfbluW6NWEM+HtYnJFa+2kJB51yqylsbUnfpWEBQDA==\"" +
                    "}" +
                    "]," +
                    "\"method\": {" +
                    "\"algorithm\": \"AES-256-GCM\"," +
                    "\"isStreamable\": true," +
                    "\"iv\": \"vL29EUoR28ZU5+b3\"" +
                    "}," +
                    "\"policy\": \"eyJib2R5Ijp7ImRhdGFBdHRyaWJ1dGVzIjpbXSwiZGlzc2VtIjpbXX0sInV1aWQiOiJlMDk0NmVhNC1mZDMzLTQ3ODktODM3Ny1hMzhiMjNhOTc1MmIifQ==\"," +
                    "\"type\": \"split\"" +
                    "}," +
                    "\"payload\": {" +
                    "\"isEncrypted\": true," +
                    "\"mimeType\": \"application/octet-stream\"," +
                    "\"protocol\": \"zip\"," +
                    "\"type\": \"reference\"," +
                    "\"url\": \"0.payload\"" +
                    "}" +
                    "};";

            writer.appendManifest(jsonString);
            writer.finish();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}