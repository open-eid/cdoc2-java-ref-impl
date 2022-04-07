# cdoc20_java

CDOC 2.0 reference implementation (Java)

TODO: CDOC 2.0 is a new and improved version of [CDOC](https://github.com/open-eid/cdoc4j), featuring additional 
security measures with optional server backend.

[CDOC 2.0 specification](https://overleaf.cloud.cyber.ee/project/61f2b8994efa0a0086c3329d)

## Structure

- cdoc20-schema - flatbuffers schemas and code generation
- cdoc20-lib    - CDOC 2.0 creation and processing library
- cdoc20-cli    - Command line utility to create/process CDOC 2.0 files

## Building
CDOC 2.0 has been tested with JDK 17 and Maven 3.8.4

```
mvn clean install
```

## Running

See `cdoc20-cli/README.md`

## Releasing

Will create tag with version v{x.y.z} in git
```
mvn clean
mvn release:prepare
mvn release:perform
```

As maven repository doesn't exist yet, then maven deploy is not performed 


