##Building & Running

###Building
Run from cdoc20 parent directory
```
mvn package
```

###Running
Run from cdoc20-cli directory

####Encryption
To create:
- Output file `/tmp/mydoc.cdoc`
- with private EC key `keys/alice.pem`
- to recipient `keys/bob_pub.pem`
- to encrypt file 'README.md'

```
java -jar target/cdoc20-cli-0.0.1-SNAPSHOT.jar create --file /tmp/mydoc.cdoc --key keys/alice.pem --pubkey keys/bob_pub.pem README.md
```

####Decryption
To decrypt:
- CDOC 2.0 file `/tmp/mydoc.cdoc`
- with decryption private EC key `keys/bob.pem`
- to output directory `/tmp`

```
java -jar target/cdoc20-cli-0.0.1-SNAPSHOT.jar decrypt --file /tmp/mydoc.cdoc --keys keys/bob.pem --output /tmp
```
