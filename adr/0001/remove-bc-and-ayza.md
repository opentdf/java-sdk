# Removing compile dependencies on BouncyCastle and Ayza libraries

## Decision
Remove compile dependencies on BouncyCastle and Ayza libraries.

## Context
### Ayza
FIPS compliance is the main force driving the decision to remove Ayza.
Ayza loads a non-FIPS BouncyCastle provider, which means that the inclusion of
the BC FIPS provider will result in errors when classes from the wrong JAR are loaded.

### BouncyCastle
Removing BouncyCastle is driven by the fact that BouncyCastle implements similar
but often not identical classes in the FIPS and non-FIPS jars; removing any
explicit dependency on BouncyCastle classes means that we are not exposed to
changes that may take place as the FIPS and non-FIPS interfaces change.

## Consequences
### Positive
* better modularity around our usage of cryptographic libraries
* makes it easier to implement FIPS compliance
* consumers of the SDK have fewer dependencies to manage
* easier testing and maintenance because we are not exposed to changes in the BouncyCastle API
### Negative
* possible increased burden to implement operations in terms of the JCA as opposed to using BouncyCastle-specific APIs