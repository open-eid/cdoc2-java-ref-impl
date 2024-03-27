# cdoc20_java

[CDOC 2.0](https://installer.id.ee/media/cdoc/cdoc_2_0_spetsifikatsioon_d-19-12_v1.9.pdf) reference implementation (Java)

CDOC 2.0 is a new version of [CDOC](https://www.id.ee/wp-content/uploads/2020/06/sk-cdoc-1.0-20120625_en.pdf) (CDOC lib [cdoc4j](https://github.com/open-eid/cdoc4j)), featuring additional security measures with optional server backend. CDoc version are not compatible. Additional background info can be found in [CDOC 2.0](https://www.ria.ee/media/2340/download).


Current CDoc 2.0 supports five scenarios

## CDoc 2.0 ECDH scenario

**Warning**: This description is simplification to give general idea, details and **final truth is in 
[CDOC 2.0 specification](https://installer.id.ee/media/cdoc/cdoc_2_0_spetsifikatsioon_d-19-12_v1.9.pdf)**.

1. Sender downloads recipient's certificate from SK LDAP using recipient id (isikukood). Recipient certificate contains
   EC public key.
2. Sender generates EC (elliptic curve) key pair using the same EC curve as in recipient EC public key [^1]
3. Sender derives key encryption key (KEK) using ECDH (from sender EC private key and recipient EC public key)  
4. Sender generates file master key (FMK) using HKDF extract algorithm
5. Sender derives content encryption key (CEK) and hmac key (HHK) from FMK using HKDF expand algorithm
6. Sender encrypts FMK with KEK (xor)
7. Sender adds encrypted FMK with senders and recipients public keys to CDoc header[^2]
8. Sender calculates header hmac using hmac key (HHK) and adds calculated hmac to CDoc
9. Sender encrypts content[^3] with CEK (ChaCha20-Poly1305 with AAD)
10. Sender sends CDoc to Recipient 
11. Recipient finds recipients public key from CDoc
12. Recipient derives key encryption key (KEK) using ECDH (from recipient private key on id-kaart and sender public key)
    and decrypts FMK
13. Recipient derives CEK and HHK from FMK using HKDF algorithm
14. Recipient calculates hmac and checks it against hmac in CDoc 
15. Recipient decrypts content using CEK

[^1]: Current specification defines only SecP384R1 Elliptic Curve for key agreement, but in future other EC curves or algorithms can be added, see flatbuffers schemas in cdoc20-schema

[^2]: Header structure is defined in flatbuffers schema, see cdoc20-schema

[^3]: Content is zlib compressed tar archive

## CDoc 2.0 ECDH server scenario

1. *Follow steps from previous scenario 1-6*
2. Sender chooses key transaction server (preconfigured list)
3. Sender sends sender public key and recipient public key to the key transfer server [^4]
4. Server stores public keys in server and generates transaction id
5. Sender adds key server id, recipient public key, transaction id and encrypted FMK to CDoc header
6. *Follow steps from previous scenario 8-10*
7. Recipient finds transaction id  and server using his id-kaart public key from CDoc
8. Recipient authenticates himself against key transfer server using certificate on id-kaart (mutual TLS)
9. Recipient queries the server with transaction id [^4]
10. If recipient certificate public key and recipient public key in transaction record match, then server answers with sender public key
11. *Follow steps from previous steps 12-15*


Key transfer server benefits:
* After the key has been deleted from the key transfer server, the document cannot be decrypted even when keys on recipient's id-kaart have been compromised.
* Other scenarios can be implemented like expiring CDoc2.0 documents by deleting expired keys from key transfer server. 

[^4]: key transfer server protocol is defined in cdoc20-openapi module

## CDoc 2.0 RSA-OAEP

RSA-OAEP is similar to ECDH scenario, with difference that KEK is generated from secure random (not ECDH) and
KEK is encrypted with recipient RSA public key and included into CDOC header (instead of
sender public key).

1. Sender acquires recipient's certificate from SK LDAP using recipient id or by some other means.
   Recipient certificate contains recipient RSA public key.
2. Sender generates file master key (FMK) using HKDF extract algorithm.
3. Sender generates encryption key (KEK) using secure random.
4. Sender derives content encryption key (CEK) and hmac key (HHK) from FMK using HKDF expand algorithm.
5. Sender encrypts FMK with KEK (xor).
6. Sender encrypts KEK with recipient's RSA public key.
7. Sender adds encrypted FMK and encrypted KEK with recipient's public key to CDoc header.
8. Sender calculates header hmac using hmac key (HHK) and adds calculated hmac to CDoc.
9. Sender encrypts content with CEK (ChaCha20-Poly1305 with AAD).
10. Sender sends CDoc to recipient.
11. Recipient searches CDoc header for recipient's record that contains his public key.
12. Recipient decrypts key encryption key (KEK) using recipient's RSA private key.
13. Recipient decrypts FMK using KEK.
14. Recipient derives CEK and HHK from FMK using HKDF algorithm.
15. Recipient calculates hmac and checks it against hmac in CDoc.
16. Recipient decrypts content using CEK.

## CDoc 2.0 RSA-OAEP with server scenario

1. *Follow steps from RSA-OAEP scenario 1-6*
2. Sender chooses key capsule server (by providing server configuration)
3. Sender sends recipient public key and encrypted KEK inside capsule to the key capsule server
4. Server stores capsule containing recipient public key and encrypted KEK and responds with generated transaction id
5. Sender adds key server id, recipient public key, transaction id and encrypted FMK to CDoc header
6. *Follow steps from RSA-OAEP scenario 8-10*
7. Recipient finds transaction id and server using his public RSA key from CDoc
8. Recipient authenticates against server using RSA certificate (mutual TLS)
9. Recipient queries the server with transaction id [^4]
10. If recipient certificate public key and recipient public key in capsule record match, then server answers with
    capsule that contains encrypted KEK
11. *Follow steps from RSA-OAEP scenario steps 12-15*

## CDoc 2.0 with symmetric key from password

Similar to Symmetric Key scenario, but symmetric key is derived from password and salt using PBKDF2 algorithm.

1. Sender and recipient have a pre shared password identified by key_label
2. Symmetric key is created from password and salt (generated using secure random) using PBKDF2 algorithm
3. Sender derives key encryption key (KEK) from symmetric key and previously generated salt using HKDF algorithm
4. *Follow steps from ECDH scenario 4-6*
5. Sender adds encrypted FMK with key_label to CDoc header
6. *Follow steps from ECDH scenario 8-10*
7. Recipient searches CDoc header for key_label and finds salt and encrypted FMK
8. Recipient derives encryption key (KEK) from salt, key_label and pre-shared symmetric key (password)
9. Recipient decrypts FMK using KEK.
10. *Follow steps from ECDH scenario 13-15*

cdoc20_java does not provide solution for securely storing the password, but most password managers
can do that.

## CDoc 2.0 with symmetric key from secret

Similar to ECDH scenario, but KEK is derived from symmetric key (secret) identified by key_label using HKDF algorithm.

1. Sender and recipient have a pre shared secret identified by key_label 
2. Sender derives key encryption key (KEK) from symmetric key, key_label and salt (generated 
   using secure random) using HKDF algorithm
3. *Follow steps from ECDH scenario 4-6*
4. Sender adds encrypted FMK with key_label to CDoc header
5. *Follow steps from ECDH scenario 8-10*
6. Recipient searches CDoc header for key_label and finds salt and encrypted FMK
7. Recipient derives encryption key (KEK) from salt, key_label and pre-shared symmetric key (secret)
8. Recipient decrypts FMK using KEK.
9. *Follow steps from ECDH scenario 13-15*

cdoc20_java does not provide solution for securely storing the secret, but most password managers
 can do that.


## Structure
[![CDOC2 Dependencies](./cdoc20-docs/arch/images/cdoc2-deps.png)](https://viewer.diagrams.net/?tags=%7B%7D&highlight=0000ff&edit=_blank&layers=1&nav=1&title=CDOC2%20deps#R3VjbcpswEP0aPybDpWDnMb4knY7bycQzbZ03BTagVCAiCxvn6yuZxYjBdpOpEzx%2Bsvbs6sI5q11wzx0lxa0gWfydh8B6jhUWPXfccxzb8x31o5F1iQz8fglEgoYYVAMz%2BgoIWojmNIRFI1ByziTNmmDA0xQC2cCIEHzVDHvirLlrRiLc0aqBWUAYtMJ%2B0VDGiNqWEf4VaBTj1gMPHQmpghFYxCTkKwNyJz13JDiX5SgpRsA0eRUv5bybPd7twQSk8i0TnucvM7h6%2BnMzvh4%2B59l1dHPPLmwfDyfX1RNDqAhAkwsZ84inhE1qdCh4noagl7WUVcdMOc8UaCvwGaRco5okl1xBsUwYeqGg8rcxnuulLj20xgWuvDHWaKTcOMJmZnlyfdy9jCC04LkIMOoh96h1%2B230egdT9%2BVe%2Fnj8mV9gkkoiIpAH4rytbirhgScgxVrNE8CIpMvmOQhmXrSNq8VRA9TnPVoNutTKuvSvDLnsg2IpAcS6nNX3KntuOut5G2u%2FynrdOxBUcQgCoz5W%2BZ3k%2B5%2Bk%2FKFDLgnLcSdGH1vJoApMpocJD%2FON9oTRKFUAgyf1aMNFRgKaRtONNXYsIyJQvGl2h0sQkqrqd40OqbNkuIqphJmarpdfqULfTJG97OvVoDCgNoGVt4%2FPiG3CxaK5MmpuVXJjo9xW1fbolLstynuOzzSNIV2qYaSHPIOUZLTyqI0M51nrsyW%2BM4G8lkCLIIaEnBXtbofXYncP%2BtJFDzpW79%2F5SO4be7%2FTZe9vl6OA0VNL9VZe7xBkf6pb%2F8r0q09N9P5pJLrxJuW8603qiDfEe%2BMNcbu8ITv6AQiVkWd1SZzmJbH9rvuBv6su6Yc5K9b7p0a77XZRnYxa5P%2FvV532H%2Bez7lBennbJsr2OVWyIaL9bxA5azAe9hCmz%2FiNu4zP%2BznQnfwE%3D)

- cdoc20-schema  - flatbuffers schemas and code generation
- cdoc20-lib     - CDOC 2.0 creation and processing library
- cdoc20-cli     - Command line utility to create/process CDOC 2.0 files
- cdoc20-openapi - OpenAPI definitions for server and client generation
- cdoc20-server  - Optional server backend for securely exchanging key capsules
- cdoc20-client  - Optional client for server backend
- gatling-tests  - Functional and load tests for cdoc20-server
- test           - Sample CDOC 2.0 containers (with script to create and decrypt them)

## Preconditions for building
* Java 17
* Maven 3.8.x
* Docker available and running (required for running tests)

## Building
CDOC 2.0 has been tested with JDK 17 and Maven 3.8.4

```
mvn clean install
```

## Testing
By default tests that require smart-card are excluded from running. To execute all tests enable allTests maven profile
```
mvn -PallTests test
```

For more control set `tests` maven property directly. For more info see 
[Junit5 Tag Expression](https://junit.org/junit5/docs/current/user-guide/#running-tests-tag-expressions)
```
mvn -Dtests='!(slow | pkcs11)'
```

### PKCS11 tests

To run the tests using a physical PKCS11 device (smart card or usb token), execute:

```
mvn test -Dtests=pkcs11
```

The pkcs11 device configuration (PKCS11 library, slot, pin, etc) can be specified using `cdoc2.pkcs11.conf-file` system property, for example:

```
mvn test -Dtests=pkcs11 -Dcdoc2.pkcs11.conf-file=pkcs11-test-safenet.properties
```

By default, the pkcs11 configuration is read from the file `pkcs11-test-idcard.properties`.

### Entropy
In case the tests run slowly (probably due to waiting on entropy generation),
using an entropy source (e.g `haveged`) may help on Linux:

```
apt-get install haveged
update-rc.d haveged defaults
service haveged start
```

## Running

See `cdoc20-cli/README.md`

## Releasing

First update CHANGELOG.md - follow semantic versioning

Will update version numbers in pom.xml files and create tag with version v{x.y.z} in git

# Non-Interactive mode without pushing changes (for release simulation)
```
mvn release:clean
mvn --batch-mode -Dtag=v{x.y.z} release:prepare -DreleaseVersion={x.y.z} -DdevelopmentVersion={x.y+1.z}-SNAPSHOT -DdryRun=true -DpushChanges=false
mvn release:perform -Darguments="-Dmaven.deploy.skip=true"
```

# Non-Interactive mode
```
mvn release:clean
mvn --batch-mode -Dtag=v{x.y.z} release:prepare -DreleaseVersion={x.y.z} -DdevelopmentVersion={x.y+1.z}-SNAPSHOT -DdeveloperConnectionUrl=scm:git:${git.repo.url}"
mvn release:perform -Darguments="-Dmaven.deploy.skip=true"
```

Verify that git repositories are synced (master points to same commit) and the tag is pushed (using `git push <remote> v{x.y.z}`).

As maven repository doesn't exist yet, then maven deploy is not performed

For more info, see
[Maven Non-interactive Release](https://maven.apache.org/maven-release/maven-release-plugin/examples/non-interactive-release.html)




