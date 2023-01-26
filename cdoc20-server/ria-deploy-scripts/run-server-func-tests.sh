#!/bin/sh

# fail on error
set -e

cd /home/riajenk/cdoc2-server
sh ./generate-gatling-test-keystores.sh
sh ./run-gatling-func-tests.sh

