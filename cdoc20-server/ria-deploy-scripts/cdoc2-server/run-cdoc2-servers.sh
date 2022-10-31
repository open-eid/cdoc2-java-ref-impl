#!/bin/sh

# stop on error
set -e

./run-cdoc2-put-server.sh
./run-cdoc2-get-server.sh

