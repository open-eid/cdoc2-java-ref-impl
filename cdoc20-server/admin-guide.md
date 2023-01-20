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

# allow only TLSv1.3
server.ssl.enabled-protocols=TLSv1.3

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
# allow only TLSv1.3
server.ssl.enabled-protocols=TLSv1.3

# The port the server is started on
server.port=8444

# Mutual TLS
server.ssl.client-auth=need
server.ssl.trust-store=/path/to/server-truststore.jks
server.ssl.trust-store-password=passwd
#cdoc20.ssl.client-auth.revocation-checks.enabled=false

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

`java -jar -Dspring.config.location=application.properties cdoc20-get-server-VER.jar`

####  Client authentication certificate revocation checking
By default, client authentication certificate revocation checking is enabled for get-server.

This option requires connection to external OCSP servers. Est-eID certificates are checked from http://aia.sk.ee/.
Depending on your network and firewall setup, it may be necessary to also configure your firewalls and/or networking proxy servers.

Timeouts in seconds for connection and read timeouts can be specified by setting
`com.sun.security.ocsp.timeout` Java system properties (-D for java executable)

To enable certificate revocation debug use `-Djava.security.debug="certpath"`

Other options available for fine-tuning certificate revocation are described in

https://docs.oracle.com/en/java/javase/17/security/java-pki-programmers-guide.html#GUID-EB250086-0AC1-4D60-AE2A-FC7461374746

To disable client certificate checking over OCSP `application.properties` must have:
```
cdoc20.ssl.client-auth.revocation-checks.enabled=false
```



## Monitoring

To enable standard Spring monitoring endpoints, `application.properties` must contain following lines:
```
# https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html#actuator.monitoring
# run management on separate port
management.server.port=18443
management.server.ssl.enabled=true
management.server.ssl.key-store-type=PKCS12
# The path to the keystore containing the certificate
# See copy-keys-and-certificates in pom.xml
management.server.ssl.key-store=../keys/cdoc20server.p12
# The password used to generate the certificate
management.server.ssl.key-store-password=passwd
# The alias mapped to the certificate
management.server.ssl.key-alias=cdoc20

# configure monitoring endpoints
management.endpoints.enabled-by-default=false
management.endpoints.web.discovery.enabled=false

# explicitly enable endpoints
management.endpoint.info.enabled=true
management.endpoint.health.enabled=true
management.endpoint.health.show-details=always
management.endpoint.startup.enabled=true

# expose endpoints
management.endpoints.web.exposure.include=info,health,startup
```

NB! Currently, the monitoring endpoints require no authentication. As these endpoints are
running on a separate HTTP port, the access to the monitoring endpoints must be implemented by network access rules (e.g firewall).


### Info endpoint 
`curl -X GET https://<management_host>:<management_port>/actuator/info | jq`

```json

{
  "build": {
    "artifact": "cdoc20-put-server",
    "name": "cdoc20-put-server",
    "time": "2023-01-17T14:31:18.918Z",
    "version": "0.3.0-SNAPSHOT",
    "group": "ee.cyber.cdoc20"
  },
  "system.time": "2023-01-17T14:48:39Z"
}
```

### Health endpoint
`curl -X GET https://<management_host>:<management_port>/actuator/health | jq`

```json
{
  "status": "UP",
  "components": {
    "db": {
      "status": "UP",
      "details": {
        "database": "PostgreSQL",
        "validationQuery": "isValid()"
      }
    },
    "diskSpace": {
      "status": "UP",
      "details": {
        "total": 499596230656,
        "free": 415045992448,
        "threshold": 10485760,
        "exists": true
      }
    },
    "ping": {
      "status": "UP"
    }
  }
}
```

### Startup endpoint
`curl -X GET https://<management_host>:<management_port>/actuator/startup | jq`

```json
{
  "springBootVersion": "2.7.5",
  "timeline": {
    "startTime": "2023-01-17T14:36:17.935227352Z",
    "events": []
  }
}
```

[^1]: https://docs.oracle.com/cd/E54932_01/doc.705/e54936/cssg_create_ssl_cert.htm#CSVSG182
