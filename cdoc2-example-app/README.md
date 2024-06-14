`cdoc-example-app` is example for cdoc2-lib and howto to convert existing cdoc file to cdoc2 file. 
It decrypts cdoc file using [cdoc4j](https://github.com/open-eid/cdoc4j) library and re-encrypts 
files in it using `cdoc2-java-ref-impl` library and creates cdoc2 file.

## Compiling and running

Requirements:

* Java17

TODO: howto setup mvn repository for getting cdoc2 dependencies (depends: GitHub maven repo)

```bash
mvnw install
```

## Run

Convert CDOC1 -> CDOC2 with password:
```bash
java -jar target/cdoc2-converter-1.0-SNAPSHOT.jar --cdoc=src/test/resources/cdoc/valid_cdoc11_ECC.cdoc -p12=src/test/resources/ecc/ecc.p12:test --cdoc2=out.cdoc2
```

Install cdoc2-cli:
```bash
mvn dependency:copy -Dartifact=ee.cyber.cdoc2:cdoc2-cli:1.2.0 -DoutputDirectory=./target
```

Decrypt `out.cdoc2`:
```bash
java -jar target/cdoc2-cli-1.2.0.jar decrypt --file=out.cdoc2 -pw
```

## Code Walkthrough

* `ee.cyber.cdoc2.converter.util.Util#reEncrypt` demonstrates howto decrypt CDOC1 file and create CDOC2
  file by re-encrypting CDOC1 files with password
* `ee.cyber.cdoc2.converter.ConverterTest#testReEncrypt` demonstrates howto decrypt CDOC2 file with password

For additional `cdoc2-lib` usage, see `EnvelopeTest` in `cdoc2-lib` project (`src/test` directory)
