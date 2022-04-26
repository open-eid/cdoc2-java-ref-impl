# Building & Running

## Building
Run from cdoc20_java parent directory
```
mvn package
```

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
java -jar target/cdoc20-cli-0.0.1-SNAPSHOT.jar create --file /tmp/mydoc.cdoc --p keys/bob_pub.pem README.md
```


### Decryption
To decrypt:
- CDOC 2.0 file `/tmp/mydoc.cdoc`
- with decryption private EC key `keys/bob.pem`
- to output directory `/tmp`

```
java -jar target/cdoc20-cli-0.0.1-SNAPSHOT.jar decrypt --file /tmp/mydoc.cdoc -k keys/bob.pem --output /tmp
```

### List

```
java -jar target/cdoc20-cli-0.0.1-SNAPSHOT.jar list --file /tmp/mydoc.cdoc -k keys/bob.pem
```



## ID-kaart (Est-id secure card)

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
- to recipient certificate `keys/37101010021.cer`
- to encrypt file 'README.md'

```
java -jar target/cdoc20-cli-0.0.1-SNAPSHOT.jar create --file /tmp/mydoc.cdoc -c keys/37101010021.cer README.md
```

### Decrypting with ID-card

To decrypt:
- CDOC file mydoc.cdoc
- use private key from ID-card slot 0 (Isikutuvastus PIN1)
- Decrypt files from cdoc file into current directory
```
java -jar target/cdoc20-cli-0.0.4-SNAPSHOT.jar decrypt -f mydoc.cdoc
```

### Troubleshooting ID-card

Verify that DigiDoc4 client is running and can access ID-card

cdoc20-cli will try to configure itself automatically. If OpenSC library is installed to non-standard location, then
specify its location by setting 'opensclibrary' property:

```
java -jar target/cdoc20-cli-0.0.4-SNAPSHOT.jar decrypt -Dopensclibrary=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so -f mydoc.cdoc
```

More tips for debugging ID-card related installation issues are provided in cdoc20-lib/pkcs11.README file