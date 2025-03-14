
This directory contains cdoc2-cli config for RIA-dev servers

TLS (POST)
https://cdoc2-keyserver.test.riaint.ee:8443

mTLS (GET)
https://cdoc2-keyserver.test.riaint.ee:8444

## Id-card
Run from cdoc2-cli directory

### Encrypt for id-card
```
java -jar target/cdoc2-cli-*.jar create --server=config/ria-test/ria-test.properties -f /tmp/ria.cdoc2 -r 38001085718 README.md
```

### Decrypting with id-card
```
java -jar target/cdoc2-cli-*.jar decrypt --server=config/ria-test/ria-test.properties -f /tmp/ria.cdoc2
```

## General EC secp384 key pair

Client certificate must be trusted by server

### Encrypt
```
java -jar target/cdoc2-cli-*.jar create --server=config/ria-test/ria-test_p12.properties -f /tmp/ria_p12.cdoc2 -p keys/cdoc2client_pub.key README.md
```

### Decrypt

```
java -jar target/cdoc2-cli-*.jar decrypt --server=config/ria-test/ria-test_p12.properties -p12 keys/cdoc2client.p12:passwd -f /tmp/ria_p12.cdoc2 -o /tmp
```
