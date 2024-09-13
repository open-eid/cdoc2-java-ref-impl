# Create temporary folders and copy needed configuration from cli config and keys folders
# Currently using cdoc2-cli/config/localhost/localhost_pkcs12.properties
# and these folders are created according to path in this file
mkdir config
cd config/
mkdir localhost
cd localhost/
cp ../../../config/server/clientconf/localhost_pkcs12.properties .
cp ../../../config/server/clientconf/clienttruststore.jks .
cd ../../
mkdir keys
cd keys/
cp ../../config/server/clientconf/cdoc2client.p12 .
cp ../../config/server/clientconf/cdoc2client_pub.key .
cp ../../config/server/clientconf/cdoc2client_priv.key .
cd ..

source variables_server.sh
source aliases_server.sh

# run docker / docker compose when servers in docker needed
# run bats docker container when bats in docker needed

# run only server tests
$BATS_HOME/bats-core/bin/bats cdoc2_server_tests.bats

# Clear config
rm -rf config/
rm -rf keys/
