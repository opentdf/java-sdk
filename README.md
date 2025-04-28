# OpenTDF Java SDK

A Java implementation of the OpenTDF protocol, and access library for the services provided by the OpenTDF platform.
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

```java
import io.opentdf.platform.sdk.Config;
import io.opentdf.platform.sdk.SDK;
import io.opentdf.platform.sdk.SDKBuilder;
import io.opentdf.platform.sdk.abac.Policy;
import java.io.InputStream;
import java.io.FileInputStream;

public class Example {
  public static void main(String[] args) {
    SDK sdk =
        new SDKBuilder
            .clientSecret("myClient", "token")
            .platformEndpoint("https://your.cluster/")
            .build();
    // Encrypt a file
    try (InputStream in = new FileInputStream("input.plaintext")) {
      Config c = Config.newTDFConfig(Config.withDataAttributes("attr1", "attr2"));
      new TDF().createTDF(in, System.out, tdfConfig, sdk.getServices().kas());
    }

    // Decrypt a file
    try (SeekableByteChannel in =
          FileChannel.open("input.ciphertext", StandardOpenOption.READ)) {
        TDF.Reader reader = new TDF().loadTDF(in, sdk.getServices().kas(), sdk.getServices().kasRegistry(), sdk.getPlatformUrl());
        reader.readPayload(System.out);
    }
}}
```

### Cryptography Library

This SDK uses the [Bouncy Castle Security library](https://www.bouncycastle.org/) library. 
Note: When using this SDK, it may be necessary to register the Bouncy Castle Provider as follows:

```java
    static{
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
