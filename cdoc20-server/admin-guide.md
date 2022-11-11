# CDOC 2.0 Key Capsule Server Administration Guide

This document describes how to configure and run CDOC2.0 key capsule servers.

## Database

The key capsule server requires a pre-installed PostgreSQL database to store data.

### Configuration

The creation and updating of the database schema is currently done from the source tree
using `liquibase-maven-plugin`. In order to create or update the database schema
Maven (at least 3.8.4) and Java (at least JDK 17) are required.

In `server-db/liquibase.properties` configure the database connection parameters to match your PostgreSQL
installation:

```
url: jdbc:postgresql://HOST/DB_NAME
username: postgres
password: secret
```

### Create and Update

To create or update the CDOC2.0 key capsule server's database run the following command from `server-db` folder:

`
mvn liquibase:update
`

## Servers

The CDOC 2.0 Key Capsule Server backend consists of two separate servers:

- CDOC 2.0 Key Capsule Put Server for sending key capsules.
- CDOC 2.0 Key Capsule Get Server for fetching key capsules.

### Keystore Creation

The servers require a keystore file to secure HTTP connections using TLS.

The keystore file is created with the `keytool` utility
(included with Java Runtime).

To generate a keystore file `cdoc20server.p12` with password `passwd`, alias `cdoc20-server` and validity of 365 days:
```
keytool -genkeypair -alias cdoc20-server -keyalg ec -groupname secp384r1 -sigalg SHA512withECDSA -keystore cdoc20server.p12 -storepass passwd -validity 365
```

For more details about operations with certificates in keystore files, see [^1].

### Put Server

#### Requirements
- Java runtime (at least JDK 17)
- the application binary `cdoc20-put-server-<VERSION>.jar`
- the configuration file `application.properties`

#### Configuration

The configuration file `application.properties` must contain the following configuration parameters:

```
# The format used for the keystore. It could be set to JKS in case it is a JKS file
server.ssl.key-store-type=PKCS12

# The path to the keystore containing the certificate
server.ssl.key-store=/path/to/cdoc20server.p12

# The keystore password to access its entries
server.ssl.key-store-password=passwd

# The alias mapped to the certificate in the keystore
server.ssl.key-alias=cdoc20-server

# Enable server TLS
server.ssl.enabled=true

# The port the server is started on
server.port=8443

# Database configuration
spring.datasource.url=jdbc:postgresql://HOST/DB_NAME
spring.datasource.username=postgres
spring.datasource.password=secret
spring.datasource.driver-class-name=org.postgresql.Driver

# logging levels
logging.level.root=info
logging.level.ee.cyber.cdoc20=trace
```

#### Running

To run the server, execute the following command:

`
java -jar -Dspring.config.location=application.properties cdoc20-put-server-VER.jar
`

### Get Server

#### Requirements
- Java runtime (at least JDK 17)
- the application binary `cdoc20-get-server-<VERSION>.jar`
- the configuration file `application.properties`

#### Truststore Configuration

The CDOC 2.0 Key Capsule Get Server must use client authentication (Mutual TLS) when returning key capsules to clients.

For mutual TLS to work, a trust store file containing trusted certificates is required.

The server truststore file is created using the `keytool` utility.

To add an entry to the trust store file `server-truststore.jks` with password `passwd` execute:

```
keytool -import -trustcacerts -file esteid2018.pem.crt -alias esteid2018 -storepass passwd -keystore server-truststore.jks
```

This will configure the Get Server to trust all requests done by Estonian ID cards signed with the esteid2018 CA certificate.


#### Configuration file

The configuration file `application.properties` must contain the following configuration parameters:

```
# The format used for the keystore. It could be set to JKS in case it is a JKS file
server.ssl.key-store-type=PKCS12

# The path to the keystore containing the certificate
server.ssl.key-store=/path/to/cdoc20server.p12

# The keystore password to access its entries
server.ssl.key-store-password=passwd

# The alias mapped to the certificate in the keystore
server.ssl.key-alias=cdoc20-server

# Enable server TLS
server.ssl.enabled=true

# The port the server is started on
server.port=8444

# Mutual TLS
server.ssl.client-auth=need
server.ssl.trust-store=/path/to/server-truststore.jks
server.ssl.trust-store-password=passwd

# Database configuration
spring.datasource.url=jdbc:postgresql://HOST/DB_NAME
spring.datasource.username=postgres
spring.datasource.password=secret
spring.datasource.driver-class-name=org.postgresql.Driver

# logging levels
logging.level.root=info
logging.level.ee.cyber.cdoc20=trace
```

#### Running

To run the server, execute the following command:

`
java -jar -Dspring.config.location=application.properties cdoc20-get-server-VER.jar
`

## Monitoring (*TODO: not implemented yet*)

Both server components return basic status info from the `https://HOST:port/status` endpoint.

The format of the response is:

HTTP status code: 200
HTTP body in json:
```
  {
    // returns the the number of successful and failed database queries since server startup
    "database": {
      "successfulRequests": 155,
      "failedRequests": 12
    }
  }
```

[^1]: https://docs.oracle.com/cd/E54932_01/doc.705/e54936/cssg_create_ssl_cert.htm#CSVSG182
