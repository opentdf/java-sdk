# java-sdk

This repository provides the OpenTDF Java SDK.
It will be available from maven central as:

```xml
    <dependency>
        <groupId>io.opentdf/platform</groupId>
        <artifactId>sdk</artifactId>
    </dependency>
```



## SDK Usage

### TDF File Creation and Reading

```java
import io.opentdf.platform.sdk.Config;
import io.opentdf.platform.sdk.SDK;
import io.opentdf.platform.sdk.SDKBuilder;
import io.opentdf.platform.sdk.abac.Policy;
import java.io.InputStream;
import java.io.FileInputStream;

public class Example {
  public static void main(String args[]) {
    SDK sdk =
        new SDKBuilder
            .clientSecret("myClient", "token")
            .platformEndpoint("https://your.cluster/")
            .build();
    // Encrypt a file
    try (InputStream in = new FileInputStream("input.plaintext")) {
      Config c = Config.newTDFConfig(Config.withDataAttributes("attr1", "attr2"))
      new TDF().createTDF(in, System.out, tdfConfig, sdk.getServices().kas());
    }

    // Decrypt a file
    try (SeekableByteChannel in =
          FileChannel.open("input.ciphertext", StandardOpenOption.READ)) {
        TDF.Reader reader = new TDF().loadTDF(in, sdk.getServices().kas());
        reader.readPayload(System.out);
    }
}
```

### Cryptography Library

The SDK uses the [Bouncy Castle Security library](https://www.bouncycastle.org/).  SDK users may need to register the Bouncy Castle Provider; e.g.:

```java
    static{
        Security.addProvider(new BouncyCastleProvider());
    }
```

### Logging

We use [slf4j](https://www.slf4j.org/), without providing a backend. We use log4j2 in our tests.

### SSL - Untrusted Certificates

Use the SDKBuilder.withSSL... methods to build an SDKBuilder with:

- An SSLFactory: ```sdkBuilder.sslFactory(mySSLFactory)```
- Directory containing trusted certificates: ```sdkBuilder.sslFactoryFromDirectory(myDirectoryWithCerts)```
- Java Keystore: ```sdkBuilder.sslFactoryFromKeyStore(keystorepath, keystorePassword)```
