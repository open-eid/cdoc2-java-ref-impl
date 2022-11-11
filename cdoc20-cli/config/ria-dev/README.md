
This directory contains cdoc20-cli config for RIA-dev servers

TLS (POST)
https://cdoc2-keyserver-01.dev.riaint.ee:8443

mTLS (GET)
https://cdoc2-keyserver-01.dev.riaint.ee:8444

## Id-card
Run from cdoc20-cli directory

### Encrypt for id-card
```
java -jar target/cdoc20-cli-0.0.10-SNAPSHOT.jar create --server=config/ria-dev/ria-dev_post.properties -f /tmp/ria.cdoc -r 37903130370 README.md
```

### Decrypting with id-card
```
java -jar target/cdoc20-cli-0.0.10-SNAPSHOT.jar decrypt --server=config/ria-dev/ria-dev_get.properties -f /tmp/ria.cdoc
```

## General EC secp384 key pair

Client certificate must be trusted by server

### Encrypt
```
java -jar target/cdoc20-cli-0.0.10-SNAPSHOT.jar create --server=config/ria-dev/ria-dev_post.properties -f /tmp/ria2.cdoc -p keys/cdoc20client_pub.pem README.md
```

### Decrypt

```
java -jar target/cdoc20-cli-0.0.10-SNAPSHOT.jar decrypt --server=config/ria-dev/ria-dev-get_pkcs12.properties -f /tmp/ria2.cdoc -k keys/cdoc20client.pem
```
