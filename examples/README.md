# OpenTDF Java SDK Examples

This directory contains example code demonstrating how to use the OpenTDF Java SDK.

## Running the Examples

The examples can be run using the `exec-maven-plugin`. The general format is:

```bash
mvn -f examples/pom.xml exec:java@<ExampleName>
```

Replace `<ExampleName>` with the name of the example you want to run. For example, to run the `EncryptExample`, use the following command:

```bash
mvn -f examples/pom.xml exec:java@EncryptExample
```

### Available Examples

*   `CreateAttribute`
*   `CreateNamespace`
*   `CreateSubjectConditionSet`
*   `CreateSubjectMapping`
*   `DecryptCollectionExample`
*   `DecryptExample`
*   `EncryptCollectionExample`
*   `EncryptExample`
*   `GetDecisions`
*   `GetEntitlements`
*   `GetManifestInformation`
*   `ListAttributes`
*   `ListNamespaces`
*   `ListSubjectMappings`

### Example with Arguments

Some examples, like `GetManifestInformation`, require command-line arguments. You can pass arguments to the examples using the `exec.args` property. For example:

```bash
mvn -f examples/pom.xml exec:java@GetManifestInformation -Dexec.args="my.ciphertext"
```
