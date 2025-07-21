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
        if (args.length < 1) {
            System.err.println("TDF file path must be provided as an argument.");
            return;
        }

        try (FileChannel tdfStream = FileChannel.open(Path.of(args[0]), StandardOpenOption.READ)) {
            Manifest manifest = SDK.readManifest(tdfStream);
            System.out.println("loaded a TDF with key access type: " + manifest.encryptionInformation.keyAccessType);

            PolicyObject policyObject = SDK.decodePolicyObject(manifest);
            System.out.println("the policy has uuid: " + policyObject.uuid);
        }
    }
}

