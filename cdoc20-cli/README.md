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

where `<version>` must be replaced with the latest version built. Example `0.0.3-SNAPSHOT`

### Encryption
To create:
- Output file `/tmp/mydoc.cdoc`
- with generated private key
- to recipient `keys/bob_pub.pem`
- to encrypt file 'README.md'

```
java -jar target/cdoc20-cli-0.0.1-SNAPSHOT.jar create --file /tmp/mydoc.cdoc -p keys/bob_pub.pem README.md
```

### Encryption with server stored keys
Server must be running, see cdoc20-server/README.md for starting the server

To store keys in key server, specify addition `--server` option:

```
java -jar target/cdoc20-cli-0.0.6-SNAPSHOT.jar create --server=server_localhost.properties -f /tmp/server_id-kaart.cdoc -r 37903130370  README.md
```

server_localhost.properties:
```
cdoc20.client.server.baseurl.post=https://localhost:8443

# trusted certificates by client
cdoc20.client.ssl.trust-store.type=JKS
cdoc20.client.ssl.trust-store=../cdoc20-server/keys/clienttruststore.jks
# or from classpath
#cdoc20.client.ssl.trust-store=classpath:keystore/clienttruststore.jks
cdoc20.client.ssl.trust-store-password=passwd

# client private certificate for mutual TLS
# client public certificate must be in server trust store
cdoc20.client.ssl.client-store.type=PKCS12
cdoc20.client.ssl.client-store=../cdoc20-server/keys/cdoc20client.p12
# alternatively load from classpath
#cdoc20.client.ssl.client-store=classpath:keystore/cdoc20client.p12
cdoc20.client.ssl.client-store-password=passwd
```


### Decryption
To decrypt:
- CDOC 2.0 file `/tmp/mydoc.cdoc`
- with decryption private EC key `keys/bob.pem`
- to output directory `/tmp`

```
java -jar target/cdoc20-cli-0.0.1-SNAPSHOT.jar decrypt --file /tmp/mydoc.cdoc -k keys/bob.pem --output /tmp
```

### Decrypting with server scenario
Server must be running, see cdoc20-server/README.md for starting the server

To decrypt CDOC document that has its keys distributed through key server, cdoc-cli must have `--server` option:

```
java -jar target/cdoc20-cli-0.0.6-SNAPSHOT.jar decrypt -f /tmp/server_id-kaart.cdoc --server=localhost_pkcs11.properties -o /tmp/
```

localhost_pkcs11.properties:
```
cdoc20.client.server.baseurl.post=https://localhost:8443

# trusted certificates by client
cdoc20.client.ssl.trust-store.type=JKS
# path to client trust store (relative or full)
cdoc20.client.ssl.trust-store=../cdoc20-server/keys/clienttruststore.jks
# or path to file in classpath (jar)
#cdoc20.client.ssl.trust-store=classpath:keystore/clienttruststore.jks
cdoc20.client.ssl.trust-store-password=passwd

# mutual TLS with cert from smart-card (EST-ID certificates are trusted by the server)
cdoc20.client.ssl.client-store.type=PKCS11
# if ssl.client-store-password.prompt is set, then ask user interactively
cdoc20.client.ssl.client-store-password.prompt=PIN1
# otherwise use password value
#cdoc20.client.ssl.client-store-password=3471

#OpenSCLibrary location, if not found in default location
#opensclibrary=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
```

### List

```
java -jar target/cdoc20-cli-0.0.1-SNAPSHOT.jar list --file /tmp/mydoc.cdoc -k keys/bob.pem
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
specify its location by setting 'opensclibrary' property:

```
java -jar target/cdoc20-cli-0.0.4-SNAPSHOT.jar decrypt -Dopensclibrary=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so -f mydoc.cdoc
```

More tips for debugging ID-card related issues are provided in cdoc20-lib/pkcs11.README file


## Other configuration options

Set with -D option

```
java -jar target/cdoc20-cli-0.0.4-SNAPSHOT.jar decrypt -Dee.cyber.cdoc20.overwrite=false -f mydoc.cdoc
```

#### opensclibrary
OpenSC library location. Default is platform specific

Common OpenSC library locations:

* For Windows, it could be C:\Windows\SysWOW64\opensc-pkcs11.dll
* For Linux, it could be /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
* For OSX, it could be /usr/local/lib/opensc-pkcs11.so



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

  