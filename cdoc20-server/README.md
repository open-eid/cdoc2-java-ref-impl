#Running locally (dev)

This file describes how to run cdoc20-server in your local development machine, without external dependencies

## Installing and creating PostgreSQL DB in Docker

### Install PostgreSQL in Docker
(Docker must be installed)
```
docker run --name cdoc20-psql -p 5432:5432 -e POSTGRES_DB=cdoc20 -e POSTGRES_PASSWORD=secret -d postgres
docker start cdoc20-psql
```

### Create DB
From server-db directory run:
```
mvn liquibase:update
```

## Compiling the server
From cdoc20-server directory run:
```
mvn clean package
```

## Running
(psql in docker must be running)
From cdoc20-server directory run:
```
java -jar -Dspring.config.location=config/application-local.properties target/cdoc20-server-0.0.6-SNAPSHOT.jar
```
where cdoc20-server-0.0.6-SNAPSHOT.jar is package built by mvn package

#Testing
## Create ServerDetails
Run from cdoc20-server/keys directory or adjust paths to certificates and keys

recipient_pub_key is public key extracted from certificate in cdoc20client.p12 file.
sender_pub_key is any EC public key with same curve as recipient_pub_key (can be reused from example below)
```
curl -v -X 'POST' \
'https://localhost:8443/ecc-details' \
--cert-type 'P12' \
--cert 'cdoc20client.p12:passwd' \
--cacert 'server-certificate.pem' \
-H 'Content-Type: application/json' \
-H 'Accept: application/json' \
-d '{
"recipient_pub_key":"BFR25IttEoB7fwzJi5KOaVMTNrfGgXlC/SilElVubX8hmGL4orYq/oP5jP6dERD7Fnw4XUk7SQgrj70moX9K+3CISafQVEvEjhhgljBLV9jSiZuB2twrkmBN7ihLGig7ew==",
"sender_pub_key":"BHvMJnfeeEGbhTieRHskVVajbcdzJ5RQDwpLK/1CR1k6o8sZpaWFBUnA/vPhFyZFL8IS3fVQPYFnRQuMqRWXRgy5WmvAZb2/pBMDb5P68aAIHYn9PGeGTFnmwg13vGskew==",
"ecc_curve": 1}' 
```
Response:
```
HTTP/1.1 201 
Location: /ecc-details/SD6efa76980f591f0cfb4966a2229505cb
```

Copy transaction id from Location header

```
curl --cert-type P12 --cert cdoc20client.p12:passwd --cacert server-certificate.pem -v -H "Content-Type: application/json" -H 'Accept: application/json' -X GET https://localhost:8443/ecc-details/SD6eab12a4e1900e58cc8da0975e8cc394
```
Response:
```
{"recipient_pub_key":"BFR25IttEoB7fwzJi5KOaVMTNrfGgXlC/SilElVubX8hmGL4orYq/oP5jP6dERD7Fnw4XUk7SQgrj70moX9K+3CISafQVEvEjhhgljBLV9jSiZuB2twrkmBN7ihLGig7ew==","sender_pub_key":"BHvMJnfeeEGbhTieRHskVVajbcdzJ5RQDwpLK/1CR1k6o8sZpaWFBUnA/vPhFyZFL8IS3fVQPYFnRQuMqRWXRgy5WmvAZb2/pBMDb5P68aAIHYn9PGeGTFnmwg13vGskew==","ecc_curve":1}
```

If the private key does not match with recipient_pub_key from the POST request, then the server returns 404 Not Found

## Generating request data from certificate

See cdoc20-server/keys/README.md how to generate client private key and EC certificate (cdoc20client.p12 and client-certificate.pem)

Extract EC public key from certificate
```
openssl x509 -pubkey -noout -in client-certificate.pem  > pubkey.pem
```

Display EC public key (TLS 1.3 format)
```
openssl ec -pubin -in pubkey.pem -text -noout
read EC key
Public-Key: (384 bit)
pub:
    04:54:76:e4:8b:6d:12:80:7b:7f:0c:c9:8b:92:8e:
    69:53:13:36:b7:c6:81:79:42:fd:28:a5:12:55:6e:
    6d:7f:21:98:62:f8:a2:b6:2a:fe:83:f9:8c:fe:9d:
    11:10:fb:16:7c:38:5d:49:3b:49:08:2b:8f:bd:26:
    a1:7f:4a:fb:70:88:49:a7:d0:54:4b:c4:8e:18:60:
    96:30:4b:57:d8:d2:89:9b:81:da:dc:2b:92:60:4d:
    ee:28:4b:1a:28:3b:7b
ASN1 OID: secp384r1
NIST CURVE: P-384
```

Base64 encode EC public key
```
openssl ec -pubin -in pubkey.pem -text -noout 2>/dev/null|grep '    '|sed s/://g|xxd -r -p -|base64|tr -d '\n' && echo ''
BFR25IttEoB7fwzJi5KOaVMTNrfGgXlC/SilElVubX8hmGL4orYq/oP5jP6dERD7Fnw4XUk7SQgrj70moX9K+3CISafQVEvEjhhgljBLV9jSiZuB2twrkmBN7ihLGig7ew==
```

Replace "recipient_pub_key" value with output

