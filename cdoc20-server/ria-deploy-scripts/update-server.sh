#!/bin/sh

# fail on error
set -e

cd /home/riajenk/cdoc2-server
sh ./update-database.sh
sh ./run-cdoc2-servers.sh

