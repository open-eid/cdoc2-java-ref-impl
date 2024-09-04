source variables.sh
source aliases.sh

# run docker / docker compose when servers in docker needed
# run bats docker container when bats in docker needed

# run every test except server tests
$BATS_HOME/bats-core/bin/bats cdoc2_tests.bats