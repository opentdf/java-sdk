package io.opentdf.platform;

import io.opentdf.platform.sdk.Manifest;
import io.opentdf.platform.sdk.PolicyObject;
import io.opentdf.platform.sdk.SDK;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

public class GetManifestInformation {
    public static void main(String[] args) throws IOException {
        FileChannel tdfStream = FileChannel.open(Path.of(args[0]), StandardOpenOption.READ);

        Manifest manifest = SDK.readManifest(tdfStream);
        System.out.println("loaded a tdf with key access type: " + manifest.encryptionInformation.keyAccessType);

        PolicyObject policyObject = SDK.decodePolicyObject(manifest);
        System.out.println("the policy has uuid: " + policyObject.uuid);
    }
}

