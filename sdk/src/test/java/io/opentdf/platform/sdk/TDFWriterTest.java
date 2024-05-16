package io.opentdf.platform.sdk;

import org.junit.jupiter.api.Test;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class TDFWriterTest {
    @Test
    void simpleTDFCreate() throws IOException {

        String kManifestJsonFromTDF = """
{
  "encryptionInformation": {
    "integrityInformation": {
      "encryptedSegmentSizeDefault": 1048604,
      "rootSignature": {
        "alg": "HS256",
        "sig": "N2Y1ZjJlYWE4N2EzNjc2Nzc3NzgxNGU2ZGE1NmI4NDNhZTI5ZWY5NDc2OGI1ZTMzYTIyMTU4MDBlZTY3NzQzNA=="
      },
      "segmentHashAlg": "GMAC",
      "segmentSizeDefault": 1048576,
      "segments": [
        {
          "encryptedSegmentSize": 41,
          "hash": "ZWEyZTkwYjZiZThmYWZhNzg5ZmNjOWIyZTA2Njg5OTQ=",
          "segmentSize": 1048576
        }
      ]
    },
    "keyAccess": [
      {
        "policyBinding": "YTgzNThhNzc5NWRhMjdjYThlYjk4ZmNmODliNzc2Y2E5ZmZiZDExZDQ3OTM5ODFjZTRjNmE3MmVjOTUzZTFlMA==",
        "protocol": "kas",
        "type": "wrapped",
        "url": "http://localhost:65432/kas",
        "wrappedKey": "dJ3PdscXWvLv/juSkL7EMhl4lgLSBfI9EeoG2ct6NeSwPkPm/ieMF6ryDQjGeqZttoLlx2qBCVpik/BooGd/FtpYMIF/7a5RFTJ3G+o4Lww/zG6zIgV2APEPO+Gp7ORlFyMNJfn6Tj8ChTweKBqfXEXLihTV6sTZFtsWjdV96Z4KXbLe8tGpkXBpUAsSlmjcDJ920vrqnp3dvt2GwfmAiRWYCMXxnqUECqN5kVXMJywcvHatv2ZJSA/ixjDOrix+MocDJ69K/yFA17DXgfjf5X4SLyS0XgaZcXsdACBb+ogBlPw6vAbBrAyqI0Vi1msMRYNDS+FTl1yWEXl1HpyyCw=="
      }
    ],
    "method": {
      "algorithm": "AES-256-GCM",
      "isStreamable": true,
      "iv": "tozen81HLtZktNOP"
    },
    "policy": "eyJib2R5Ijp7ImRhdGFBdHRyaWJ1dGVzIjpbXSwiZGlzc2VtIjpbXX0sInV1aWQiOiJiNTM3MDllMy03NmE3LTRmYzctOGEwZi1mZDBhNjcyNmVhM2YifQ==",
    "type": "split"
  },
  "payload": {
    "isEncrypted": true,
    "mimeType": "application/octet-stream",
    "protocol": "zip",
    "type": "reference",
    "url": "0.payload"
  }
}
              """;
        String payload = "Hello, world!";
        FileOutputStream fileOutStream = new FileOutputStream("sample.tdf");
        TDFWriter writer = new TDFWriter(fileOutStream);
        writer.appendPayload(payload.getBytes());
        writer.appendManifest(kManifestJsonFromTDF);
        writer.finish();
        fileOutStream.close();
    }
}
