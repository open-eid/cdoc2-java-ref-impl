# cdoc20_java

[CDOC 2.0](https://overleaf.cloud.cyber.ee/project/61f2b8994efa0a0086c3329d) reference implementation (Java)

CDOC 2.0 is a new version of [CDOC](https://github.com/open-eid/cdoc4j), featuring additional 
security measures with optional server backend. CDoc version are not compatible.

Current CDoc 2.0 supports two scenarios, one similar to original CDoc 1.0 and second with optional server backend.

## TL;DR CDoc 2.0 without server scenario 

**Warning**: This description is simplification to give general idea, details and **final truth is in [CDOC 2.0 specification](https://overleaf.cloud.cyber.ee/project/61f2b8994efa0a0086c3329d)**.

1. Sender generates EC (elliptic curve) key pair [^1]
2. Sender finds recipient's certificate that contains EC public key from SK LDAP
3. Sender derives key encryption key (KEK) using ECDH (from sender EC private key and recipient EC public key)  
4. Sender generates file master key (FMK) from secure random
5. Sender derives content encryption key (CEK) and hmac key from FMK using HKDF algorithm
6. Sender encrypts CEK with KEK (xor)
7. Sender adds KEK and senders and recipients public keys to CDoc header[^2]
8. Sender calculates header hmac using hmac key (HHK) and adds calculated hmac to CDoc
9. Sender encrypts content[^3] with CEK (ChaCha20-Poly1305 with AAD)
10. Sender sends CDoc to Recipient 
11. Recipient finds recipients public key from CDoc
12. Recipient derives key encryption key (KEK) using ECDH (from recipient private key on id-kaart and sender public key) and decrypts FMK
13. Recipient derives CEK and HHK from FMK using HKDF algorithm
14. Recipient calculates hmac and checks it against hmac in CDoc 
15. Recipient decrypts content using CEK

[^1]: Current specification defines only SecP384R1 Elliptic Curve for key agreement, but in future other EC curves or algorithms can be added, see flatbuffers schemas in cdoc20-schema

[^2]: Header structure is defined in flatbuffers schema, see cdoc20-schema

[^3]: Content is zlib compressed tar archive

## TL;DR CDoc 2.0 with optional server scenario

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
11. Server deletes transaction record
12. *Follow steps from previous steps 12-15*


Key transfer server benefits:
* After the key has been deleted from the key transfer server, the document can't be decrypted even when keys on recipient id-kaart have been compromised
* Other scenarios can be implemented like expiring CDoc2.0 documents by deleting expired keys from key transfer server. 

[^4]: key transfer server protocol is defined in cdoc20-openapi module



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

First update CHANGELOG.md

Will create tag with version v{x.y.z} in git
```
mvn clean
mvn release:prepare
mvn release:perform
```

As maven repository doesn't exist yet, then maven deploy is not performed 


