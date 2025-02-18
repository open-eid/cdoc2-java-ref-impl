#!/bin/bash

# Output PKCS#12 keystore file
KEYSTORE_FILE="mobileid_demo_server_trusted_ssl_certs.p12"

# Keystore password
KEYSTORE_PASSWORD="passwd"

# Check if keytool is installed
if ! command -v keytool &> /dev/null; then
    echo "Error: keytool is not installed. Please install it and try again."
    exit 1
fi

# Remove existing keystore file if needed
[ -f "$KEYSTORE_FILE" ] && rm -f "$KEYSTORE_FILE"

# Import each .crt or .cer file into the keystore
for cert_file in *.crt *.cer *.pem; do
    if [ -f "$cert_file" ]; then
        # Extract the base name without the extension as the alias
        alias=$(basename "$cert_file" | sed 's/\.[^.]*$//')

        echo "Importing $cert_file with alias '$alias'..."
        keytool -importcert -trustcacerts \
            -file "$cert_file" \
            -alias "$alias" \
            -keystore "$KEYSTORE_FILE" \
            -storetype PKCS12 \
            -storepass "$KEYSTORE_PASSWORD" -noprompt
    fi
done

echo "PKCS#12 keystore created: $KEYSTORE_FILE"
echo

# List certificates with aliases and SHA-1 fingerprints so that fingerprint can be compared with
# https://www.skidsolutions.eu/resources/certificates/#Test-certificates
echo "Aliases, Serial Numbers, and SHA-1 fingerprints in $KEYSTORE_FILE:"

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
echo "Compare to certificates in https://www.skidsolutions.eu/resources/certificates/#Test-certificates"


