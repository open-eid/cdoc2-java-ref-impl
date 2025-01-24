#!/bin/bash

# Output PKCS#12 keystore file
KEYSTORE_FILE="mobileid_demo_server_trusted_ssl_certs.p12"

# Keystore password
KEYSTORE_PASSWORD="passwd"


keytool -list -v -keystore "$KEYSTORE_FILE" -storetype PKCS12 -storepass "$KEYSTORE_PASSWORD" \
    | awk '
    BEGIN { alias=""; serial=""; fingerprint=""; }
    /Alias name:/ {
        alias=substr($0, index($0, ":") + 2);
        printf "Alias: %s\n", alias;
    }
    /Serial number:/ {
        serial=substr($0, index($0, ":") + 2);
        printf "  Serial Number: %s\n", serial;
    }
    /SHA1:/ {
        fingerprint=substr($0, index($0, ":") + 2);
        printf "  SHA-1: %s\n\n", fingerprint;
    }
    '
