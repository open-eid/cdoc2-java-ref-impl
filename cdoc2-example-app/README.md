`cdoc-example-app` is example for cdoc2-lib and howto to convert existing cdoc file to cdoc2 file. 
It decrypts cdoc file using [cdoc4j](https://github.com/open-eid/cdoc4j) library and re-encrypts 
files in it using `cdoc2-java-ref-impl` library and creates cdoc2 file.

## Compiling and running

Requirements:

* Java17

Configure cdoc2 maven dependencies: https://github.com/open-eid/cdoc2-java-ref-impl/tree/master?tab=readme-ov-file#maven-dependencies

```bash
mvn install
```

## Run


Install cdoc2-cli:
```bash
mvn dependency:copy -Dartifact=ee.cyber.cdoc2:cdoc2-cli:1.6.0 -DoutputDirectory=./target
```

Convert CDOC1 -> CDOC2 with password:
```bash
java -jar target/cdoc2-example-app-1.1-SNAPSHOT.jar cdoc-convert --cdoc=src/test/resources/cdoc/valid_cdoc11_ECC.cdoc -p12=src/test/resources/ecc/ecc.p12:test --cdoc2=out.cdoc2
```

Decrypt `out.cdoc2`:
```bash
java -jar target/cdoc2-cli-1.6.0.jar decrypt --file=out.cdoc2 -pw
```

Create ASICE file:
```bash
java -jar target/cdoc2-example-app-1.1-SNAPSHOT.jar asic -f digidoc4j.asice README.md pom.xml
```

#### `.asic` container encryption

* Files from unsigned `.asic` container are extracted before encryption, then encrypted/decrypted.
* Signed `.asic` container is encrypted and decrypted without files extraction from it.
  `.asic` container opening and signature verification is a very extensive process and will take 
  few minutes to print log messages in about 78MB. Read explanation [here](https://github.com/open-eid/digidoc4j/wiki/Questions-&-Answers#why-is-the-library-that-slow).
  Create signed container example `signed.asice` and test the encryption:

Encrypt signed ASICE -> CDOC2 with password:
```bash
java -jar target/cdoc2-example-app-1.1-SNAPSHOT.jar asic-convert --asic=src/test/resources/asic/signed.asice --cdoc2=signedAsic.cdoc2
```

Encrypt non-signed ASICE -> CDOC2 with password:
```bash
java -jar target/cdoc2-example-app-1.1-SNAPSHOT.jar asic-convert --asic=src/test/resources/asic/no-signature.asice --cdoc2=extractedFiles.cdoc2 --tmp=/tmp 
```


## Code Walkthrough

* `ee.cyber.cdoc2.converter.util.Util#reEncrypt` demonstrates howto decrypt CDOC1 file and create CDOC2
  file by re-encrypting CDOC1 files with password
* `ee.cyber.cdoc2.converter.ConverterTest#testReEncrypt` demonstrates howto decrypt CDOC2 file with password

For additional `cdoc2-lib` usage, see `EnvelopeTest` in `cdoc2-lib` project (`src/test` directory)
