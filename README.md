# java-sdk

OpenTDF Java SDK

### SDK Usage
The SDK uses the [Bouncy Castle Security library](https://www.bouncycastle.org/).  SDK users may need to register the Bouncy Castle Provider; e.g.:
```
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
