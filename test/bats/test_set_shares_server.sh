# Create temporary folders and copy needed configuration from cli config and keys folders
mkdir config
cd config/
mkdir localhost
cd localhost/
cp ../../../config/shares-server/clientconf/clienttruststore.jks .
cd ../../
mkdir keys
cd keys/
cp ../../config/shares-server/clientconf/cdoc2client.p12 .
cd ..

source variables_server.sh
source aliases_server.sh

# run docker / docker compose when shares servers in docker needed
# run bats docker container when bats in docker needed

# run only shares-server tests
echo BATS_OPTS=$BATS_OPTS
$BATS_HOME/bats-core/bin/bats $BATS_OPTS cdoc2_shares_server_tests.bats

# Clear config
rm -rf config/
rm -rf keys/
