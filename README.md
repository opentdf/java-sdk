# OpenTDF Java SDK

A Java implementation of the OpenTDF protocol, and access library for the services provided by the OpenTDF platform.

**New to the OpenTDF SDK?** See the [OpenTDF SDK Quickstart Guide](https://opentdf.io/category/sdk) for a comprehensive introduction.

This SDK is available from Maven central as:

```xml
    <dependency>
        <groupId>io.opentdf/platform</groupId>
        <artifactId>sdk</artifactId>
    </dependency>
```
### Additional Maven Modules
- cmdline: Command line utility

## Quick Start Example

This example demonstrates how to create and read TDF (Trusted Data Format) files using the OpenTDF SDK.

**Prerequisites:** Follow the [OpenTDF Quickstart](https://opentdf.io/quickstart) to get a local platform running, or if you already have a hosted version, replace the values with your OpenTDF platform details.

For more code examples, see:
- [Creating TDFs](https://opentdf.io/sdks/tdf)
- [Managing policy](https://opentdf.io/sdks/policy)

```java
package io.opentdf.platform;

import io.opentdf.platform.sdk.Config;
import io.opentdf.platform.sdk.SDK;
import io.opentdf.platform.sdk.SDKBuilder;
import io.opentdf.platform.sdk.TDF;

import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public class Example {
    public static void main(String[] args) throws Exception {
        // Initialize SDK with platform endpoint and authentication
        // Replace these values with your actual configuration:
        String platformEndpoint = "localhost:8080";           // Your platform URL
        String clientId = "opentdf";                          // Your OAuth client ID
        String clientSecret = "secret";                       // Your OAuth client secret
        String kasUrl = "http://localhost:8080/kas";          // Your KAS URL

        SDK sdk = new SDKBuilder()
                .platformEndpoint(platformEndpoint)
                .clientSecret(clientId, clientSecret)
                .useInsecurePlaintextConnection(true)         // Only for local development with HTTP
                .build();

        // Create a TDF
        // This attribute is created in the quickstart guide
        String dataAttribute = "https://opentdf.io/attr/department/value/finance";

        String plaintext = "Hello, world!";
        var plaintextInputStream = new ByteArrayInputStream(plaintext.getBytes(StandardCharsets.UTF_8));

        var kasInfo = new Config.KASInfo();
        kasInfo.URL = kasUrl;

        var tdfConfig = Config.newTDFConfig(
            Config.withKasInformation(kasInfo),
            Config.withDataAttributes(dataAttribute)
        );

        // Write encrypted TDF to file
        try (FileOutputStream out = new FileOutputStream("encrypted.tdf")) {
            sdk.createTDF(plaintextInputStream, out, tdfConfig);
        }

        System.out.println("TDF created successfully");

        // Decrypt the TDF
        // LoadTDF contacts the Key Access Service (KAS) to verify that this client
        // has been granted access to the data attributes, then decrypts the TDF.
        // Note: The client must have entitlements configured on the platform first.
        Path tdfPath = Paths.get("encrypted.tdf");
        try (FileChannel tdfChannel = FileChannel.open(tdfPath, StandardOpenOption.READ)) {
            TDF.Reader reader = sdk.loadTDF(tdfChannel, Config.newTDFReaderConfig());

            // Write the decrypted plaintext to a file
            try (FileOutputStream out = new FileOutputStream("output.txt")) {
                reader.readPayload(out);
            }
        }

        System.out.println("Successfully created and decrypted TDF");
    }
}
```

### Configuration Values

Replace these placeholder values with your actual configuration:

| Variable | Default (Quickstart) | Description |
|----------|---------------------|-------------|
| `platformEndpoint` | `localhost:8080` | Your OpenTDF platform URL |
| `clientId` | `opentdf` | OAuth client ID (from quickstart) |
| `clientSecret` | `secret` | OAuth client secret (from quickstart) |
| `kasUrl` | `http://localhost:8080/kas` | Your Key Access Service URL |
| `dataAttribute` | `https://opentdf.io/attr/department/value/finance` | Data attribute FQN (created in quickstart) |

**Before running:**
1. Follow the [OpenTDF Quickstart](https://opentdf.io/quickstart) to start the platform
2. Create an OAuth client in Keycloak and note the credentials
3. Grant your client entitlements to the `department` attribute (see [Managing policy](https://opentdf.io/sdks/policy))

**Expected Output:**
```
TDF created successfully
Successfully created and decrypted TDF
```

The `output.txt` file will contain the decrypted plaintext: `Hello, world!`

### Cryptography Library

This SDK uses the [Bouncy Castle Security library](https://www.bouncycastle.org/) library. 
Note: When using this SDK, it may be necessary to register the Bouncy Castle Provider as follows:

```java
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
```

### Logging

The Java SDK makes use of the [slf4j](https://www.slf4j.org/) library, without providing a backend. log4j2 in leveraged within the included automated tests.

### SSL - Untrusted Certificates

Leverage the SDKBuilder.withSSL methods to create an SDKBuilder as follows:

- An SSLFactory: ```sdkBuilder.sslFactory(mySSLFactory)```
- Directory containing trusted certificates: ```sdkBuilder.sslFactoryFromDirectory(myDirectoryWithCerts)```
- Java Keystore: ```sdkBuilder.sslFactoryFromKeyStore(keystorepath, keystorePassword)```

### Buf

Create an account, link that account with GitHub and then under User settings create a `token`

```shell
[INFO] --- antrun:3.1.0:run (generateSources) @ sdk ---
[INFO] Executing tasks
[INFO]      [exec] Failure: too many requests
[INFO]      [exec] 
[INFO]      [exec] Please see https://buf.build/docs/bsr/rate-limits for details about BSR rate limiting.
```

## Release Process

### SNAPSHOT

Snapshots are from main latest

```shell
mvn versions:set -DnewVersion=1.2.3-SNAPSHOT
```

### RELEASE

Releases are from tags created by the GitHub release process.
Enter 'Release Please' to trigger the release process.
