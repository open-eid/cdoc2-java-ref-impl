##Building & Running

###Building
Run from cdoc20_java parent directory
```
mvn package
```

###Running
Run from cdoc20-cli directory

Latest help can be seen by running:
```
java -jar target/cdoc20-cli-<version>.jar
```

where `<version>` must be replaced with the latest version built. Example `0.0.3-SNAPSHOT`

####Encryption
To create:
- Output file `/tmp/mydoc.cdoc`
- with private EC key `keys/alice.pem`
- to recipient `keys/bob_pub.pem`
- to encrypt file 'README.md'

```
java -jar target/cdoc20-cli-0.0.1-SNAPSHOT.jar create --file /tmp/mydoc.cdoc --key keys/alice.pem --pubkeys keys/bob_pub.pem README.md
```

####Decryption
To decrypt:
- CDOC 2.0 file `/tmp/mydoc.cdoc`
- with decryption private EC key `keys/bob.pem`
- to output directory `/tmp`

```
java -jar target/cdoc20-cli-0.0.1-SNAPSHOT.jar decrypt --file /tmp/mydoc.cdoc --keys keys/bob.pem --output /tmp
```

####List

```
java -jar target/cdoc20-cli-0.0.1-SNAPSHOT.jar LIST --file /tmp/mydoc.cdoc --keys keys/bob.pem
```