
This directory contains cdoc2-cli config for RIA-dev servers

TLS (POST)
https://cdoc2-keyserver.dev.riaint.ee:8443

mTLS (GET)
https://cdoc2-keyserver.dev.riaint.ee:8444

## Id-card
Run from cdoc2-cli directory

### Encrypt for id-card
```
java -jar target/cdoc2-cli-*.jar create --server=config/ria-dev/ria-dev.properties -f /tmp/ria.cdoc -r 38001085718 README.md
```

### Decrypting with id-card
```
java -jar target/cdoc2-cli-*.jar decrypt --server=config/ria-dev/ria-dev.properties -f /tmp/ria.cdoc
```

## General EC secp384 key pair

Client certificate must be trusted by server

### Encrypt
```
java -jar target/cdoc2-cli-*.jar create --server=config/ria-dev/ria-dev_pkcs12.properties -f /tmp/ria_p12.cdoc -p keys/cdoc2client_pub.key README.md
```

### Decrypt

```
java -jar target/cdoc2-cli-*.jar decrypt --server=config/ria-dev/ria-dev_pkcs12.properties -p12 keys/cdoc2client.p12:passwd -f /tmp/ria_p12.cdoc -o /tmp
```

### Encrypt for Smart-ID

```
java -jar target/cdoc2-cli-*.jar create \
-Dkey-shares.properties=config/ria-dev/key-shares.properties \
-Dsmart-id.properties=config/smart-id/smart-id.properties \
--smart-id=30303039914 \
-f /tmp/SID_30303039914.cdoc2 \
README.md
```

### Decrypt with Smart-ID

```
java -jar target/cdoc2-cli-*.jar decrypt \
-Dkey-shares.properties=config/ria-dev/key-shares.properties \
-Dsmart-id.properties=config/smart-id/smart-id.properties \
--smart-id=30303039914 \
-f /tmp/SID_30303039914.cdoc2 \
-o /tmp
```

