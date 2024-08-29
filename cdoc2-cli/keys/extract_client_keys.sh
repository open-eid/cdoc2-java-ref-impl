#!/usr/bin/env bash

cd ../..
PROJECT_DIR=$(pwd)
KEYS_DIR=${PROJECT_DIR}/cdoc2-cli/keys

# fetching updated client certificate and key store (have to be commited at source remote repository)
git remote add source "$REMOTE_REPOSITORY"
echo "# Fetching source..."
git fetch source
echo "# Checkout source branch $SOURCE_BRANCH_NAME/keys"
git checkout source/"$SOURCE_BRANCH_NAME" -- keys
echo "# Got following files in keys directory:"
git status --branch --short

echo "# Checkout destination branch $DESTINATION_BRANCH_NAME"
git checkout -b "$DESTINATION_BRANCH_NAME"
echo "# Moving client key store cdoc2client.p12 to cdoc2-cli/keys..."
mv keys/cdoc2client.p12 cdoc2-cli/keys
echo "# Moving client certificate client-certificate.pem to cdoc2-cli/keys..."
mv keys/ca_certs/client-certificate.pem cdoc2-cli/keys
echo "# Renaming client certificate to cdoc2client-certificate.pem..."
mv cdoc2-cli/keys/client-certificate.pem cdoc2-cli/keys/cdoc2client-certificate.pem
echo "# Removing unnecessary fetched files..."
rm -rf keys

git remote remove source "$REMOTE_REPOSITORY"
cd "$KEYS_DIR" || exit


# Extract private key from pkcs12 format keystore
echo "# Beginning to extract private and public keys..."
openssl pkcs12 -in cdoc2client.p12 -nodes -nocerts -passin pass:passwd -out temp_all_keys.key
awk -vwant=cdoc2-client '/friendlyName:/{sel=($2==want)} /^-----BEGIN/,/^-----END/{if(sel)print}' temp_all_keys.key > cdoc2client_priv.key
rm temp_all_keys.key
# Convert it to EC PRIVATE KEY using below command:
openssl ec -in cdoc2client_priv.key -out cdoc2client_priv.key -passin pass:passwd
echo "# Private key is extracted."

# Extract public key from certificate
openssl x509 -inform pem -in cdoc2client-certificate.pem -pubkey -out temp_public.key
awk '/^-----BEGIN PUBLIC KEY/,/^-----END PUBLIC KEY/' temp_public.key > cdoc2client_pub.key
rm temp_public.key
echo "# Public key is extracted."
