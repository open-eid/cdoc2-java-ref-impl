# CDOC

CDOC stands for 'Crypto Digidoc', encrypted file transmission format used in the [Estonian eID](https://github.com/open-eid) ecosystem.

([Digidoc](https://www.id.ee/en/article/digidoc-container-format-life-cycle-2/) is digital signature format specific to Estonia)

* CDOC1 - Unofficial term for all (XML-ENC based) CDOC formats preceding CDOC2.
* [CDOC2](https://open-eid.github.io/CDOC2) is a new version of CDOC, featuring additional security
  measures with optional server backend and support for long term cryptography.

CDOC1 and CDOC2 version are not compatible.

End-user software to create/decrypt CDOC1/CDOC2: https://github.com/open-eid/DigiDoc4-Client

Additional background info can be found in [RIA CDOC2 presentation](https://www.youtube.com/watch?v=otrO2A6TuGQ)
and [id.ee CDOC 2.0 article](https://www.id.ee/artikkel/cdoc-2-0/)

# Format differences between CDOC1 and CDOC2

## CDOC1

CDOC1 is xml document, examples can be found [here](https://github.com/open-eid/cdoc4j/blob/master/src/test/resources/cdoc/)

```
~/workspace/cdoc2-java-ref-impl/cdoc2-example-app/src/test/resources/cdoc$ head -1 valid_cdoc11_ECC.cdoc 
<?xml version="1.0" encoding="UTF-8"?><denc:EncryptedData xmlns:denc="http://www.w3.org/2001/04/xmlenc#" MimeType="application/octet-stream">
```

[CDOC1 specification](https://www.id.ee/wp-content/uploads/2020/06/sk-cdoc-1.0-20120625_en.pdf) and
Java library [cdoc4j](https://github.com/open-eid/cdoc4j)

To create/decrypt CDOC1 documents see [cdoc4j: Examples of how to use it](https://github.com/open-eid/cdoc4j/wiki/Examples-of-how-to-use-it)

## CDOC2

CDOC2 is binary document, where first 4 bytes are `0x43, 0x44, 0x4f, 0x43` or `CDOC` in ASCII:
```
~/workspace/cdoc2-java-ref-impl/test/testvectors$ hd ec_simple.cdoc 
00000000  43 44 4f 43 02 00 00 01  6c 0c 00 00 00 08 00 0c  |CDOC....l.......|
```

[CDOC2 specification](https://open-eid.github.io/CDOC2) and Java library
[cdoc2-java-ref-impl](https://github.com/open-eid/cdoc2-java-ref-impl)

# cdoc2-java-ref-impl

`cdoc2-java-ref-impl` is a [repository](https://github.com/open-eid/cdoc2-java-ref-impl) that contains `cdoc2-lib` and related submodules required for
creating/decrypting CDOC2 documents. To use modules from `cdoc2-java-ref-impl`:

## Configure GitHub Maven package registry

To use `cdoc2-java-ref-impl` as Maven dependency you need to [create a GitHub personal access token](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-apache-maven-registry#authenticating-to-github-packages)
with `read:packages` scope.

Configure [Maven settings.xml](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-apache-maven-registry#authenticating-with-a-personal-access-token)
or [configure Gradle](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-gradle-registry)

Example `<profile>` section of `settings.xml` for using cdoc2 dependencies:
```xml
  <profile>
      <id>github</id>
      <repositories>
        <repository>
          <id>central</id>
          <url>https://repo1.maven.org/maven2</url>
        </repository>
        <repository>
          <id>github</id>
          <url>https://maven.pkg.github.com/open-eid/cdoc2-java-ref-impl</url>
        </repository>
      </repositories>
  </profile>
```

Test that you have configured your Maven `settings.xml` correctly (from `cdoc2-example-app` directory):

```
./mvnw dependency::get -Dartifact=ee.cyber.cdoc2:cdoc2-lib:2.0.0
```
```
[INFO] Resolving ee.cyber.cdoc2:cdoc2-lib:jar:2.0.0 with transitive dependencies
Downloading from central: https://repo1.maven.org/maven2/ee/cyber/cdoc2/cdoc2-lib/2.0.0/cdoc2-lib-2.0.0.pom
Downloading from github: https://maven.pkg.github.com/open-eid/cdoc2-capsule-server/ee/cyber/cdoc2/cdoc2-lib/2.0.0/cdoc2-lib-2.0.0.pom
Downloaded from github: https://maven.pkg.github.com/open-eid/cdoc2-capsule-server/ee/cyber/cdoc2/cdoc2-lib/2.0.0/cdoc2-lib-2.0.0.pom (3.2 kB at 2.3 kB/s)
Downloading from central: https://repo1.maven.org/maven2/ee/cyber/cdoc2/cdoc2-lib/2.0.0/cdoc2-lib-2.0.0.jar
Downloading from github: https://maven.pkg.github.com/open-eid/cdoc2-capsule-server/ee/cyber/cdoc2/cdoc2-lib/2.0.0/cdoc2-lib-2.0.0.jar
Downloaded from github: https://maven.pkg.github.com/open-eid/cdoc2-capsule-server/ee/cyber/cdoc2/cdoc2-lib/2.0.0/cdoc2-lib-2.0.0.jar (157 kB at 136 kB/s)
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
```

Latest version of `cdoc2-lib` can be found [here](https://github.com/open-eid/cdoc2-java-ref-impl/packages/2223168)

## cdoc2-lib usage

Define `cdoc2-lib` dependency in your `pom.xml`:
```xml
<dependency>
    <groupId>ee.cyber.cdoc2</groupId>
    <artifactId>cdoc2-lib</artifactId>
    <version>2.0.0</version>
</dependency>
```

[Full example](https://github.com/open-eid/cdoc2-java-ref-impl/blob/master/cdoc2-example-app/pom.xml)

### To create CDOC2 document with password:
```java
        File cdoc2FileToCreate = Paths.get("/tmp/first.cdoc2").toFile();
        File payloadFile1 = Paths.get("some_file1.txt").toFile();
        File payloadFile2 = Paths.get("some_file2.txt").toFile();
        File[] payloadFiles = new File[]{payloadFile1, payloadFile2};
        char[] password = "myPlainTextPassword".toCharArray(); // don't store password in String in production code
        Sting keyLabel = "labelFromExample";
 
        EncryptionKeyMaterial km = EncryptionKeyMaterial.fromPassword(password, keyLabel);
        
        CDocBuilder builder = new CDocBuilder()
            .withPayloadFiles(Arrays.asList(payloadFiles))
            .withRecipients(List.of(km))
            .buildToFile(cdoc2FileToCreate);
```

### To decrypt with password:
```java
        Path cdoc2FileToDecrypt = Paths.get("/tmp/first.cdoc2");
        Path destDir = Paths.get("/tmp");
        char[] password = "myPlainTextPassword".toCharArray(); // don't store password in String in production code
        Sting keyLabel = "labelFromExample";

        List<String> extractedFileNames = new CDocDecrypter()
            .withCDoc(cdoc2FileToDecrypt.toFile())
            .withRecipient(DecryptionKeyMaterial.fromPassword(password, keyLabel))
            .withDestinationDirectory(destDir.toFile())
            .decrypt();
```

### To create cdoc2 document for id-card:
```java
        File cdoc2FileToCreate = Paths.get("/tmp/second.cdoc2").toFile();
        String identificationCode = "3..."; // your id-code
        File[] payloadFiles = new File[]{};//add some files

        List<EncryptionKeyMaterial> recipients =      
            EncryptionKeyMaterial.collectionBuilder().fromEId(new String[]{identificationCode});
        CDocBuilder builder = new CDocBuilder()
            .withPayloadFiles(Arrays.asList(payloadFiles))
            .withRecipients(recipients)
            .buildToFile(cdoc2FileToCreate);
```

**Note**: this works only for end user id-cards. It doesn't work for test id-cards as test-id card
certificates are not in [SK LDAP](https://github.com/SK-EID/LDAP/wiki/Knowledge-Base).

### To decrypt with id-card you need a smart device and physical ID card:

Using id-card requires that you have openSC PKCS11 drivers installed. These are usually installed
by installing https://www.id.ee/en/article/install-id-software/ Before trying to decrypt CDOC2 files
with `cdoc2-lib` verify that you can access id-card with

```java
        Path cdoc2FileToDecrypt = Paths.get("/tmp/second.cdoc2");
        Path destDir = Paths.get("/tmp");
        Integer slot = 0;
        String alias = "Isikutuvastus";
        DecryptionKeyMaterial dkm = DecryptionKeyMaterial.fromKeyPair(
            Pkcs11Tools.loadFromPKCS11Interactively(
                "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so", // pkcs11 driver location, differs on different platforms 
                slot, 
                alias
            )
        );
        
        List<String> extractedFiles = new CDocDecrypter()
                .withCDoc(cdoc2FileToDecrypt.toFile())
                .withRecipient(dkm)
                .withDestinationDirectory(destDir.toFile())
                .decrypt();
```
`/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so` is location of OpenSC pkcs11 driver library. Some info
on setting up pcks11 on Ubuntu can be found in [pkcs11.README](https://github.com/open-eid/cdoc2-java-ref-impl/blob/master/cdoc2-lib/pkcs11.README)

## CDOC2 server scenario usage

Most cdoc2 documents created by DigiDoc4 library will use [cdoc2-capsule-server](https://github.com/open-eid/cdoc2-capsule-server)

### Checking CDOC2 recipients

To determine, what kind of recipient can decrypt CDOC2 document and if [cdoc2-capsule-server](https://github.com/open-eid/cdoc2-capsule-server)
was used, see source code for [cdoc2-cli info](https://github.com/open-eid/cdoc2-java-ref-impl/blob/f91a917fc0fb47f35e9e4f69de4d0108b620d00d/cdoc2-cli/src/main/java/ee/cyber/cdoc2/cli/commands/CDocInfoCmd.java#L46)

### Create CDOC2 document with key material stored in server.

To create CDOC2 document with server scenario, [cdoc2-capsule-server](https://github.com/open-eid/cdoc2-capsule-server) client needs to be configured.
Easiest is to use one of existing properties files from [cdoc2-cli/config](https://github.com/open-eid/cdoc2-java-ref-impl/tree/master/cdoc2-cli/config/)
directory and `.withServerProperties` method:

```java
        File cdoc2FileToCreate = Paths.get("/tmp/second.cdoc2").toFile();
        String identificationCode = "3..."; // your id-code
        String keyServerPropertiesFile = "/path/to/cdoc2-cli/conf/id.properties"; 
        Properties p = new Properties().load(
            Resources.getResourceAsStream(keyServerPropertiesFile));

        List<EncryptionKeyMaterial> recipients =      
            EncryptionKeyMaterial.collectionBuilder().fromEId(new String[]{identificationCode});
        CDocBuilder builder = new CDocBuilder()
            .withServerProperties(p)
            .withPayloadFiles(Arrays.asList(payloadFiles))
            .withRecipients(recipients)
            .buildToFile(cdoc2FileToCreate);
```
**Note**: `cdoc2-cli/config` contains usually several properties files. For id-card usage, use one with
the shortest name (without `_pkcs12` or `_p12` in name).

Uploading key material to server allows to invalidate CDOC2 documents that are may be affected from
future security vulnerability like [ROCA vulnerability](https://en.wikipedia.org/wiki/ROCA_vulnerability)

In non-server scenarios sender public key material is included in CDOC2 itself. For server scenarios
sender public key material is uploaded to server and recipient needs first to download the
sender public key material and then needs to decrypt CDOC2 with private key. Even when data stored
in server gets compromised, it doesn't grant access to CDOC2 documents as final decryption is done
with recipient private key (id-card).

### Decrypting with key material from the server

Similar to previous example, to decrypt cdoc2 with server recipient,
[cdoc2-capsule-server](https://github.com/open-eid/cdoc2-capsule-server)client needs to be configured
and easiest is to do it with existing properties, but `CdocDecrypter` has method `withKeyServers`
that takes `KeyCapsuleClientFactory` as parameter:


```java
    Path cdoc2FileToDecrypt = Paths.get("/tmp/second.cdoc2");
    Path destDir = Paths.get("/tmp");
    Integer slot = 0;
    String alias = "Isikutuvastus";
    
    String keyServerPropertiesFile = "/path/to/cdoc2-cli/conf/id.properties";
    Properties p = new Properties().load(
        Resources.getResourceAsStream(keyServerPropertiesFile));
    KeyCapsuleClientFactory keyCapsulesClient = KeyCapsuleClientImpl.createFactory(p);
    
    DecryptionKeyMaterial dkm = DecryptionKeyMaterial.fromKeyPair(
        Pkcs11Tools.loadFromPKCS11Interactively(
            "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so", // pkcs11 driver location, differs on different platforms 
            slot, 
            alias
        )
    );

    List<String> extractedFiles = new CDocDecrypter()
        .withCDoc(cdoc2FileToDecrypt.toFile())
        .withKeyServers(keyCapsulesClient)
        .withRecipient(dkm)
        .withDestinationDirectory(destDir.toFile())
        .decrypt();
```

**Note**: `pkcs11-library` location can also be specified as Java system property 
(`-Dpkcs11-library=<path>` or `System.setProperty("pkcs11-library", "<path>")`), 
when not specified explicitly as method parameter. If `pkcs11-library` system property is not set,
then pkcs11 library is looked for from [default locations](https://github.com/open-eid/cdoc2-java-ref-impl/blob/ae1351db7e13c3ede58a48757ae53c2c80166a70/cdoc2-lib/src/main/java/ee/cyber/cdoc2/crypto/Pkcs11Tools.java#L404)

### Latest server configuration

Latest server configuration is available through https://id.eesti.ee/config.json


## Long-term crypto

Scenarios with id-card are meant for transport cryptography only as id-card certificates expiry and
also cdoc2-capsule-server deletes key material after some time. To store CDOC2 documents for longer time,
it's recommended to re-encrypt CDOC2 documents with a password or symmetric key. When re-encrypting,
then files in CDOC2 container are not written to disk - only parts of CDOC2 are decrypted temporary
into memory. To re-encrypt existing CDOC2 document, use [CDocReEncrypter](cdoc2-lib/src/main/java/ee/cyber/cdoc2/CDocReEncrypter.java) class

For usage see [CDocReEncryptCmd.java](https://github.com/open-eid/cdoc2-java-ref-impl/blob/f91a917fc0fb47f35e9e4f69de4d0108b620d00d/cdoc2-cli/src/main/java/ee/cyber/cdoc2/cli/commands/CDocReEncryptCmd.java) from `cdoc2-cli`

# CDOC sample code

See [cdoc2-example-app](https://github.com/open-eid/cdoc2-java-ref-impl/tree/master/cdoc2-example-app) -
uses both `cdoc4j` and `cdoc2-lib`