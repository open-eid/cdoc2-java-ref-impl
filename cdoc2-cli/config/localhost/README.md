For testing server scenarios with cdoc2 capsule servers running on localhost.

TLS (POST)
https://localhost:8443

mTLS (GET)
https://localhost:8444

## Running server

Prerequisites: [docker compose](https://docs.docker.com/compose/install/) is installed  
```
cd cdoc2-java-ref-impl/test/config/server
docker compose up
```

## Id-card

Requirements:
* [id-card (pkcs11) drivers](https://www.id.ee/) are installed

Run from cdoc2-cli directory

### Encrypt for id-card
```
java -jar target/cdoc2-cli-*.jar create --server=config/localhost/localhost.properties -f /tmp/localhost.cdoc -r 38001085718 README.md
```
Replace `3800108571` with your id code

### Decrypting with id-card
```
java -jar target/cdoc2-cli-*.jar decrypt --server=config/localhost/localhost.properties -f /tmp/localhost.cdoc -o /tmp
```

If Pkcs11 driver is not found from default location, then alternative location can be provided with 
`-Dpkcs11-library=<path>` option, for example
```
java -jar target/cdoc2-cli-*.jar decrypt -Dpkcs11-library=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
```
