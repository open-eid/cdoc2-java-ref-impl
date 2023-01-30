# Building & Running

## Building
Run from cdoc20_java parent directory
```
mvn clean package
```

Will create `cdoc20-cli/target/cdoc20-cli-<version>.jar`

## Running
Run from cdoc20-cli directory

Latest help can be seen by running:
```
java -jar target/cdoc20-cli-<version>.jar
```

where `<version>` must be replaced with the latest version built. Example `0.0.12-SNAPSHOT`

Sample generated CDOC2 documents are located at `cdoc20_java/test/testvectors`

Commands for creating and decrypting sample files using cdoc-cli are in `cdoc20_java/test/generate_documents.sh`


### Encryption
To create:
- Output file `/tmp/mydoc.cdoc`
- with generated private key
- to recipient `keys/bob_pub.pem`
- to encrypt file 'README.md'

```
java -jar target/cdoc20-cli-0.0.1-SNAPSHOT.jar create --file /tmp/mydoc.cdoc -p keys/bob_pub.pem README.md
```

### Encryption with server scenario
Server must be running, see cdoc20-server/README.md for starting the server

To store keys in key server, specify addition `--server` option:

When encrypting for est-eid card, `-r` <id-code> can be used
```
java -jar target/cdoc20-cli-0.0.12-SNAPSHOT.jar create --server=config/localhost/localhost.properties -f /tmp/localhost_id-card.cdoc -r 37903130370 README.md
```

Optionally cdoc20-cli also supports encrypting with "soft" key or certificate

Public key (`-p`)
```
java -jar target/cdoc20-cli-0.0.12-SNAPSHOT.jar create --server=config/localhost/localhost.properties -f /tmp/localhost.cdoc -p keys/cdoc20client_pub.pem README.md
```

Certificate (`-c` option):
```
java -jar target/cdoc20-cli-0.0.12-SNAPSHOT.jar create --server=config/localhost/localhost.properties -f /tmp/localhost.cdoc -c keys/cdoc20client-certificate.pem README.md
```

### Encryption with symmetric key

Generate key with openssl (minimum length 32 bytes):
```
openssl rand -base64 32
`HHeUrHfo+bCZd//gGmEOU2nA5cgQolQ/m18UO/dN1tE=`
```

Base64 encoded keys must be prefixed with 'base64,', so that key becomes "base64,HHeUrHfo+bCZd//gGmEOU2nA5cgQolQ/m18UO/dN1tE="

Encrypt with generated key and label 'mylabel':
```
java -jar target/cdoc20-cli-0.0.13-SNAPSHOT.jar create --secret "mylabel:base64,HHeUrHfo+bCZd//gGmEOU2nA5cgQolQ/m18UO/dN1tE=" -f /tmp/symmetric.cdoc README.md
```

Or clear text:
```
java -jar target/cdoc20-cli-0.0.13-SNAPSHOT.jar create --secret "mylongpasswd:longstringthatIcanremember,butothersdon'tknow" -f /tmp/symmetric.cdoc README.md
```

Or secret read from file (so that secret is not exposed through process list)
```
java -jar target/cdoc20-cli-0.0.13-SNAPSHOT.jar create @keys/b64secret.option -f /tmp/symmetric.cdoc README.md
```

```
cat keys/b64secret.option
--secret "label_b64secret:base64,aejUgxxSQXqiiyrxSGACfMiIRBZq5KjlCwr/xVNY/B0="
```

Decryption is done with the same label and key used for encryption
```
java -jar target/cdoc20-cli-0.0.13-SNAPSHOT.jar decrypt @keys/b64secret.option -f /tmp/symmetric.cdoc -o /tmp
```

Key and label can be safely stored in a password manager.



### Decryption
To decrypt:
- CDOC 2.0 file `/tmp/mydoc.cdoc`
- with decryption private EC key `keys/bob.pem`
- to output directory `/tmp`

```
java -jar target/cdoc20-cli-0.0.12-SNAPSHOT.jar decrypt --file /tmp/mydoc.cdoc -k keys/bob.pem --output /tmp
```

### Decrypting with server scenario
Server must be running, see cdoc20-server/README.md for starting the server

To decrypt CDOC document that has its keys distributed through key server, cdoc-cli must have `--server` option:

Configuration for id-card (certificate for mutual TLS and private key is read from smart-card)
```
java -jar target/cdoc20-cli-0.0.12-SNAPSHOT.jar decrypt --server=config/localhost/localhost.properties -f /tmp/localhost_id-card.cdoc -o /tmp/
```

It is also possible to decrypt documents created with "soft" keys, but configuration for mutual TLS (properties file) and
key (read separately from a file) must match. Also, server must be configured to trust client certificate used for
mutual TLS.
```
java -jar target/cdoc20-cli-0.0.12-SNAPSHOT.jar decrypt --server=config/localhost/localhost_pkcs12.properties -f /tmp/localhost.cdoc -k keys/cdoc20client.pem -o /tmp/
```


### List

```
java -jar target/cdoc20-cli-0.0.1-SNAPSHOT.jar list --file /tmp/mydoc.cdoc -k keys/bob.pem
```

or

```
java -jar target/cdoc20-cli-0.0.12-SNAPSHOT.jar list --server=config/localhost/localhost_pkcs12.properties -f /tmp/localhost.cdoc -k keys/cdoc20client.pem
```

### List recipients

List recipients. Prints recipient types and key labels from CDOC header.

```
java -jar target/cdoc20-cli-0.0.13-SNAPSHOT.jar info -f /tmp/id.cdoc
```


## ID-kaart (Est-id secure card)


### Encrypting for ID-card owner

cdoc20-cli can download authentication certificate (Isikutuvastus PIN1) from SK LDAP directory 
https://www.skidsolutions.eu/repositoorium/ldap/esteid-ldap-kataloogi-kasutamine/

To create cdoc for recipient with id code 37101010021 use:
```
java -jar target/cdoc20-cli-0.0.5-SNAPSHOT.jar create --file /tmp/mydoc.cdoc -r 37101010021 README.md
```


### Decrypting with ID-card

To decrypt:
- CDOC file mydoc.cdoc
- use private key from ID-card slot 0 (Isikutuvastus PIN1)
- Decrypt files from cdoc file into current directory
```
java -jar target/cdoc20-cli-0.0.4-SNAPSHOT.jar decrypt -f mydoc.cdoc
```

### Certificate extraction

* Run DigiDoc4 client
* Crypto -> Add file (choose random file)
* Recipients -> Certificate from card -> click on certificate -> Show Certificate -> Save

Saved certificate will be .cer file (same as der)

or

* Run DigiDoc4 client
* Crypto -> Add file (choose random file)
* Recipients -> Enter personal code -> Search -> Show Certificate -> Save


### Encrypting documents with certificate

To create:
- Output file `/tmp/mydoc.cdoc`
- with generated private key
- to recipient with certificate `keys/37101010021.cer` (DER or PEM formats are supported)
- to encrypt file 'README.md'

```
java -jar target/cdoc20-cli-0.0.1-SNAPSHOT.jar create --file /tmp/mydoc.cdoc -c keys/37101010021.cer README.md
```


### Troubleshooting ID-card

Verify that DigiDoc4 client is running and can access ID-card

cdoc20-cli will try to configure itself automatically. If OpenSC library is installed to non-standard location, then
specify its location by setting 'pkcs11-library' property:

```
java -jar target/cdoc20-cli-0.0.4-SNAPSHOT.jar decrypt -Dpkcs11-library=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so -f mydoc.cdoc
```

More tips for debugging ID-card related issues are provided in cdoc20-lib/pkcs11.README file


## Other configuration options

Set with -D option

```
java -jar target/cdoc20-cli-0.0.4-SNAPSHOT.jar decrypt -Dee.cyber.cdoc20.overwrite=false -f mydoc.cdoc
```

#### pkcs11-library
PKCS11 library location. Default is platform specific

Common OpenSC library locations:

* For Windows, it could be C:\Windows\SysWOW64\opensc-pkcs11.dll
* For Linux, it could be /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
* For OSX, it could be /usr/local/lib/opensc-pkcs11.so

## SafeNet eToken support

Requirements:
* OpenSC is installed
* SafeNet Authentication Client (provides the pkcs11 library) is installed.
  See https://knowledge.digicert.com/generalinformation/INFO1982.html for details.
* Create an OpenSC configuration file `opensc-safenet.cfg` for the USB device in the following format

```
name=SafeNet-eToken
library=/usr/lib/libeToken.so
slot=1
```

To find the slot for the SafeNet eToken, execute:

```
pkcs11-tool --module /usr/lib/libeToken.so -L
```

List entries on the eToken device:

```
keytool -providerclass sun.security.pkcs11.SunPKCS11 -providerarg opensc-safenet.cfg -storetype PKCS11 -storepass YOUR-SAFENET-PIN -list
```

Export Certificate from the SafeNet eToken device:

```
keytool -providerclass sun.security.pkcs11.SunPKCS11 -providerarg opensc-safenet.cfg -storetype PKCS11 -storepass YOUR-SAFENET-PIN -alias YOUR_ENTRY_ALIAS -exportcert -rfc -file etoken-cert.pem
```

Encrypt certificate as described in the "Encrypting documents with certificate" section.

List files encrypted for the eToken device by specifying pkcs11 library, slot and key alias:

```
java -jar target/cdoc20-cli-0.0.13-SNAPSHOT.jar list -f file-for-etoken.cdoc -Dpkcs11-library=/usr/lib/libeToken.so -s 2 -a cdoc2-test
```

Decrypt files encrypted for the eToken device by specifying pkcs11 library, slot and key alias:

```
java -jar target/cdoc20-cli-0.0.13-SNAPSHOT.jar decrypt -f file-for-etoken.cdoc -Dpkcs11-library=/usr/lib/libeToken.so -s 2 -a cdoc2-test
```

#### ee.cyber.cdoc20.overwrite 
When decrypting, is overwriting files allowed. Default is true

#### ee.cyber.cdoc20.maxDiskUsagePercentage
default 98.0

Decrypting will be stopped if disk usage is over  maxDiskUsagePercentage


#### ee.cyber.cdoc20.tarEntriesThreshold
default 1000

Decrypting will be stopped if container contains over tarEntriesThreshold entries (files)


#### ee.cyber.cdoc20.compressionThreshold
default 10.0

Decrypting will be stopped if compressed file compression ratio is over compressionThreshold

