#!/usr/bin/env bash

source variables_server.sh

# set up servers (could use --wait --wait-timeout 60s with latest docker compose healthchecks defined)
docker compose -f "$TESTING_DIR/../config/shares-server/docker-compose.yml" up -d

# not needed as already in bats dir?
#cd "$TESTING_DIR"

/usr/bin/env bash test_set_shares_server.sh

docker compose -f "$TESTING_DIR/../config/shares-server/docker-compose.yml" down
