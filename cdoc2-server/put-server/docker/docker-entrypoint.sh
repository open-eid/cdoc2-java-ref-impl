#!/usr/bin/env bash

## default JAVA_OPTS, overwritten by env variable of same name
JAVA_OPTS="${JAVA_OPTS:=-XX:InitialRAMPercentage=30 -XX:MinRAMPercentage=50 -XX:MaxRAMPercentage=80}"

cd /opt/cdoc2

echo "Running ${NAME}"
exec java $JAVA_OPTS -jar cdoc2-put-server.jar
