package io.opentdf.platform.sdk;

import org.junit.jupiter.api.Test;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ManifestTest {
    @Test
    void testManifestMarshalAndUnMarshal()  {
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

        GsonBuilder gsonBuilder = new GsonBuilder();
        Gson gson = gsonBuilder.setPrettyPrinting().create();
        Manifest manifest = gson.fromJson(kManifestJsonFromTDF, Manifest.class);

        // Test payload
        assertEquals(manifest.payload.url, "0.payload");
        assertEquals(manifest.payload.isEncrypted, true);

        // Test encryptionInformation
        assertEquals(manifest.encryptionInformation.keyAccessType, "split");
        assertEquals(manifest.encryptionInformation.keyAccessObj.size(), 1);

        List<Manifest.KeyAccess> keyAccess = manifest.encryptionInformation.keyAccessObj;
        assertEquals(keyAccess.get(0).keyType, "wrapped");
        assertEquals(keyAccess.get(0).protocol, "kas");

        assertEquals(manifest.encryptionInformation.method.algorithm, "AES-256-GCM");
        assertEquals(manifest.encryptionInformation.integrityInformation.rootSignature.algorithm, "HS256");
        assertEquals(manifest.encryptionInformation.integrityInformation.segmentHashAlg, "GMAC");
        assertEquals(manifest.encryptionInformation.integrityInformation.segments.get(0).segmentSize, 1048576);

        System.out.println(gson.toJson(manifest));


        Manifest.Payload payload = new Manifest.Payload();
        payload.protocol = "zip";

        Manifest.EncryptionInformation encryptionInformation = manifest.encryptionInformation;
        encryptionInformation.policy = "updated policy";

        Manifest newManifest = new Manifest();
        newManifest.payload = payload;
        newManifest.encryptionInformation = encryptionInformation;

        System.out.println(gson.toJson(newManifest));
    }
}
