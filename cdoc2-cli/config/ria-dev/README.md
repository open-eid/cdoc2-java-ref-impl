
This directory contains cdoc2-cli config for RIA-dev servers

TLS (POST)
https://cdoc2-keyserver-01.dev.riaint.ee:8443

mTLS (GET)
https://cdoc2-keyserver-01.dev.riaint.ee:8444

## Id-card
Run from cdoc2-cli directory

### Encrypt for id-card
```
java -jar target/cdoc2-cli-*.jar create --server=config/ria-dev/ria-dev.properties -f /tmp/ria.cdoc -r 37903130370 README.md
```

### Decrypting with id-card
```
java -jar target/cdoc2-cli-*.jar decrypt --server=config/ria-dev/ria-dev.properties -f /tmp/ria.cdoc
```

## General EC secp384 key pair

Client certificate must be trusted by server

### Encrypt
```
java -jar target/cdoc2-cli-*.jar create --server=config/ria-dev/ria-dev_pkcs12.properties -f /tmp/ria2.cdoc -p keys/cdoc2client_pub.pem README.md
```

### Decrypt

```
java -jar target/cdoc2-cli-*.jar decrypt --server=config/ria-dev/ria-dev_pkcs12.properties -f /tmp/ria2.cdoc -k keys/cdoc2client.pem
```
