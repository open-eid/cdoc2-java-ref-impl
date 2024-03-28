# Building & Running

## Building

Run from cdoc20_java parent directory

``` {.bash}
mvn clean package
```

It will create `cdoc20-cli/target/cdoc20-cli-<version>.jar`

## Running

Run from the cdoc20-cli directory:

``` {.bash}
java -jar target/cdoc20-cli-<version>.jar
```

where `<version>` must be replaced with the latest version built. Example: `0.0.12-SNAPSHOT`.

Sample generated CDOC2 documents are located at: `cdoc20_java/test/testvectors`

Commands for creating and decrypting sample files using cdoc-cli are in: `cdoc20_java/test/generate_documents.sh`

### Encryption

In order to encrypt a file locally with a private key, use the ´create´ command.

**Options:**

- `--file` - output container file. Example: `/tmp/mydoc.cdoc`
- `-p` - recipient public key. Example: `keys/bob_pub.pem`

Provide files as the last argument. Example: `README.md`

``` {.bash}
java -jar target/cdoc20-cli-*.jar create --file /tmp/mydoc.cdoc -p keys/bob_pub.pem README.md
```

### Encryption with server scenario

Server must be running, see cdoc20-server/README.md for starting the server.

To store keys in key server, specify addition `--server` option.

When encrypting for est-eid card, `-r <id-code>` can be used.

``` {.bash}
java -jar target/cdoc20-cli-*.jar create --server=config/localhost/localhost.properties -f /tmp/localhost_id-card.cdoc -r 37903130370 README.md
```

Optionally cdoc20-cli also supports encrypting with "soft" key or certificate.

Public key is provided with the option `-p`.

``` {.bash}
java -jar target/cdoc20-cli-*.jar create --server=config/localhost/localhost.properties -f /tmp/localhost.cdoc -p keys/cdoc20client_pub.pem README.md
```

Certificate (`-c` option):

``` {.bash}
java -jar target/cdoc20-cli-*.jar create --server=config/localhost/localhost.properties -f /tmp/localhost.cdoc -c keys/cdoc20client-certificate.pem README.md
```

### Encryption with symmetric key

Generate a key with openssl (minimum length 32 bytes):

``` {.bash}
openssl rand -base64 32
`HHeUrHfo+bCZd//gGmEOU2nA5cgQolQ/m18UO/dN1tE=`
```

Base64 encoded keys must be prefixed with 'base64,', so that key becomes "base64,HHeUrHfo+bCZd//gGmEOU2nA5cgQolQ/m18UO/dN1tE="

Encrypt with generated key and label 'label_b64secret':

``` {.bash}
java -jar target/cdoc20-cli-*.jar create --secret "label_b64secret:base64,aejUgxxSQXqiiyrxSGACfMiIRBZq5KjlCwr/xVNY/B0=" -f /tmp/symmetric.cdoc README.md
```

Or secret read from file (so that secret is not exposed through process list).

``` {.bash}
java -jar target/cdoc20-cli-*.jar create @keys/b64secret.option -f /tmp/symmetric.cdoc README.md
```

``` {.bash}
cat keys/b64secret.option --secret "label_b64secret:base64,aejUgxxSQXqiiyrxSGACfMiIRBZq5KjlCwr/xVNY/B0="
```

Or encrypt with password clear text (note, that password also can be encoded to base64 format, as secret):

``` {.bash}
java -jar target/cdoc20-cli-*.jar create --password "passwordlabel:myPlainTextPassword" -f /tmp/symmetric.cdoc README.md
```

Decryption is done with the same label and key used for encryption

``` {.bash}
java -jar target/cdoc20-cli-*.jar decrypt @keys/b64secret.option -f /tmp/symmetric.cdoc -o /tmp
```

Or with the same label and password used for encryption:

``` {.bash}
java -jar target/cdoc20-cli-*.jar decrypt --password "passwordlabel:myPlainTextPassword" -f /tmp/symmetric.cdoc --output /tmp
```

Or with the same label and secret used for encryption:

``` {.bash}
java -jar target/cdoc20-cli-*.jar decrypt --secret "label_b64secret:base64,aejUgxxSQXqiiyrxSGACfMiIRBZq5KjlCwr/xVNY/B0=" -f /tmp/symmetric.cdoc --output /tmp
```

Key and label can be safely stored in a password manager.

### Decryption

To decrypt supply the following options:

- `--file` - CDOC 2.0 file `/tmp/mydoc.cdoc`
- `-k` - with decryption private EC key `keys/bob.pem`
- `--output` - to output directory `/tmp`

``` {.bash}
java -jar target/cdoc20-cli-*.jar decrypt --file /tmp/mydoc.cdoc -k keys/bob.pem --output /tmp
```

### Decrypting with server scenario

Server must be running, see cdoc20-server/README.md for starting the server

To decrypt CDOC document that has its keys distributed through key server, cdoc-cli must have `--server` option:

Configuration for id-card (certificate for mutual TLS and private key is read from smart-card)

``` {.bash}
java -jar target/cdoc20-cli-*.jar decrypt --server=config/localhost/localhost.properties -f /tmp/localhost_id-card.cdoc -o /tmp/
```

It is also possible to decrypt documents created with "soft" keys, but configuration for mutual TLS (properties file) and key (read separately from a file) must match. Also, server must be configured to trust client certificate used for mutual TLS.

``` {.bash}
java -jar target/cdoc20-cli-*.jar decrypt --server=config/localhost/localhost_pkcs12.properties -f /tmp/localhost.cdoc -k keys/cdoc20client.pem -o /tmp/
```

### Re-encryption with password for long time storage

First encrypt the document:

``` {.bash}
java -jar target/cdoc20-cli-*.jar create --secret "mylongpasswd:longstringthatIcanremember,butothersdon'tknow" -f /tmp/symmetric.cdoc README.md
```

Create different directory for re-encrypted container:

``` {.bash}
mkdir -p /tmp/cdoc2
```

Then re-encrypt it with password for long-term storage:

``` {.bash}
java -jar target/cdoc20-cli-*.jar re-encrypt --encpassword "passwordlabel:myPlainTextPassword" --secret "mylongpasswd:longstringthatIcanremember,butothersdon'tknow" -f /tmp/symmetric.cdoc --output /tmp/cdoc2
```

For testing decryption ensure the correct re-encrypted container location:

``` {.bash}
java -jar target/cdoc20-cli-*.jar decrypt --password "passwordlabel:myPlainTextPassword" -f /tmp/cdoc2/symmetric.cdoc --output /tmp/cdoc2
```

### List

``` {.bash}
java -jar target/cdoc20-cli-*.jar list --file /tmp/mydoc.cdoc -k keys/bob.pem
```

or with server scenario:

``` {.bash}
java -jar target/cdoc20-cli-*.jar list --server=config/localhost/localhost_pkcs12.properties -f /tmp/localhost.cdoc -k keys/cdoc20client.pem
```

or with password:

``` {.bash}
java -jar target/cdoc20-cli-*.jar list --file /tmp/symmetric.cdoc --password "passwordlabel:myPlainTextPassword"
```

or with secret:

``` {.bash}
java -jar target/cdoc20-cli-*.jar list --file /tmp/symmetric.cdoc --secret "label_b64secret:base64,aejUgxxSQXqiiyrxSGACfMiIRBZq5KjlCwr/xVNY/B0="
```

### List recipients

List recipients. Prints recipient types and key labels from CDOC header.

``` {.bash}
java -jar target/cdoc20-cli-*.jar info -f /tmp/id.cdoc
```

## ID-kaart (Est-id secure card)

### Encrypting for ID-card owner

cdoc20-cli can download authentication certificate (user authentication PIN1) from [SK LDAP directory](https://www.skidsolutions.eu/repositoorium/ldap/esteid-ldap-kataloogi-kasutamine/).

To create a CDOC2.0 container for a recipient with an ID code 37101010021, use:

``` {.bash}
java -jar target/cdoc20-cli-*.jar create --file /tmp/mydoc.cdoc -r 37101010021 README.md
```

### Decrypting with ID-card

To decrypt use the following option:

- `-f` - CDOC file mydoc.cdoc

Also:

- use private key from ID-card slot 0 (user authentication PIN1)
- Decrypt files from cdoc file into current directory

``` {.bash}
java -jar target/cdoc20-cli-*.jar decrypt -f mydoc.cdoc
```

### Certificate extraction

- Run DigiDoc4 client
- Crypto -> Add file (choose random file)
- Recipients -> Certificate from card -> click on certificate -> Show Certificate -> Save

Saved certificate will be .cer file (same as der)

or

- Run DigiDoc4 client
- Crypto -> Add file (choose random file)
- Recipients -> Enter personal code -> Search -> Show Certificate -> Save

### Encrypting documents with certificate

To create:

- Output file `/tmp/mydoc.cdoc`
- with generated private key
- to recipient with certificate `keys/cdoc2client-certificate.pem` (DER or PEM formats are supported)
- to encrypt file 'README.md'

``` {.bash}
java -jar target/cdoc20-cli-*.jar create --file /tmp/mydoc.cdoc -c keys/cdoc20client-certificate.pem README.md
```

Decrypt created container with private key:

``` {.bash}
java -jar target/cdoc20-cli-*.jar decrypt -f /tmp/mydoc.cdoc -k keys/cdoc20client.pem --output /tmp
```

### Troubleshooting ID-card

Verify that DigiDoc4 client is running and can access ID-card.

cdoc20-cli will try to configure itself automatically. If OpenSC library is installed to a non-standard location, then specify its location by setting 'pkcs11-library' property:

``` {.bash}
java -jar target/cdoc20-cli-*.jar decrypt -Dpkcs11-library=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so -f mydoc.cdoc
```

More tips for debugging ID-card related issues are provided in the cdoc20-lib/pkcs11.README file.

## Other configuration options

Set with -D option

``` {.bash}
java -jar target/cdoc20-cli-*.jar decrypt -D ee.cyber.cdoc20.overwrite=false -f mydoc.cdoc
```

**pkcs11-library**
Default: is platform specific
PKCS11 library location.

Common OpenSC library locations:

- For Windows, it could be C:\Windows\SysWOW64\opensc-pkcs11.dll
- For Linux, it could be /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
- For OSX, it could be /usr/local/lib/opensc-pkcs11.so

## SafeNet eToken support

Requirements:

- OpenSC is installed
- SafeNet Authentication Client (provides the pkcs11 library) is installed.
  For details [see](https://knowledge.digicert.com/generalinformation/INFO1982.html).
- Create an OpenSC configuration file `opensc-safenet.cfg` for the USB device in the following format

``` {.cfg}
name=SafeNet-eToken
library=/usr/lib/libeToken.so
slot=1
```

To find the slot for the SafeNet eToken, execute:

``` {.bash}
pkcs11-tool --module /usr/lib/libeToken.so -L
```

List entries on the eToken device:

``` {.bash}
keytool -providerclass sun.security.pkcs11.SunPKCS11 -providerarg opensc-safenet.cfg -storetype PKCS11 -storepass YOUR-SAFENET-PIN -list
```

Export Certificate from the SafeNet eToken device:

``` {.bash}
keytool -providerclass sun.security.pkcs11.SunPKCS11 -providerarg opensc-safenet.cfg -storetype PKCS11 -storepass YOUR-SAFENET-PIN -alias YOUR_ENTRY_ALIAS -exportcert -rfc -file etoken-cert.pem
```

Encrypt certificate as described in the "Encrypting documents with certificate" section.

List files encrypted for the eToken device by specifying pkcs11 library, slot and key alias:

``` {.bash}
java -jar target/cdoc20-cli-*.jar list -f file-for-etoken.cdoc -Dpkcs11-library=/usr/lib/libeToken.so -s 2 -a cdoc2-test
```

Decrypt files encrypted for the eToken device by specifying pkcs11 library, slot and key alias:

``` {.bash}
java -jar target/cdoc20-cli-*.jar decrypt -f file-for-etoken.cdoc -Dpkcs11-library=/usr/lib/libeToken.so -s 2 -a cdoc2-test
```

**ee.cyber.cdoc20.overwrite**
Default: false

When decrypting, is overwriting files allowed.

**ee.cyber.cdoc20.maxDiskUsagePercentage**
Default: 98.0

Decrypting will be stopped if disk usage is over  maxDiskUsagePercentage

**ee.cyber.cdoc20.tarEntriesThreshold**
Default: 1000

Decrypting will be stopped if container contains over tarEntriesThreshold entries (files)

**ee.cyber.cdoc20.compressionThreshold**
Default: 10.0

Decrypting will be stopped if compressed file compression ratio is over compressionThreshold
