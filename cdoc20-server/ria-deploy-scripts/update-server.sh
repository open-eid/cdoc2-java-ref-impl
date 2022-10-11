#!/bin/sh

# fail on error
set -e

cd /path/to/cdoc2-server
sh ./update-database.sh
sh ./run-cdoc2-server.sh

