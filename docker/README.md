# Build and run CDOC 2.0 components

## Build binaries

Follow the instructions in [Main README](../README.md#building) to build all Java binaries

## Start CDOC 2.0 Key Capsule Server using Docker Compose

To install the latest Docker Compose version see https://docs.docker.com/compose/install/

In `cdoc20_java/docker`  directory run
```
docker compose up
```

This will create the database and CDOC 2.0 Key Capsule servers.
The servers use self-signed test certificates and keystores found in `cdoc_java/cdoc20_server/keys`

For more details on creating server certificates and trust stores, see [Generating Server keystore](../cdoc20-server/keys/README.md).

## Testing

### Server health check

CDOC 2.0 Key Capsule servers provide a health-check endpoint.
To verify that the servers are working properly, execute:

```
curl -k https://localhost:18443/actuator/health
```

and

```
curl -k https://localhost:18444/actuator/health
```

### Encrypt a file using CDOC 2.0 Key Capsule Server

In the `cdoc20_java/cdoc20_cli` folder execute:

```
java -jar target/cdoc20-cli-*.jar create \
  --server=config/localhost/localhost.properties \
  -f /path/to/enrypted-file.cdoc \
  -r EST_ID_CODE \
  /path/to/input-file
```

Replace `EST_ID_CODE` with the Estonian identification code of the recipient.

### Decrypt a file using CDOC 2.0 Key Capsule Server

In the `cdoc20_java/cdoc20_cli` folder execute:

```
java -jar target/cdoc20-cli*.jar decrypt \
  --server=config/localhost/localhost.properties \
  -f /path/to/enrypted-file.cdoc \
  -o /path/to/derypted-file.cdoc
```

For more details on how to use `cdoc20-cli` see [CDOC 2.0 CLI](../cdoc20-cli/README.md).

