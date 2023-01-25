#!/bin/sh

DOCKER_IMAGE=harbor.riaint.ee/cdoc2/cdoc20-put-server

CONTAINER_NAME=cdoc20-put-server

docker pull $DOCKER_IMAGE

docker stop $CONTAINER_NAME
docker rm -f $CONTAINER_NAME

# decrease thread count (default 250) to run on machine with 1 GB RAM
docker run -d --restart unless-stopped --name $CONTAINER_NAME --user "$(id -u):$(id -g)" \
    -p 8443:8443 \
    -p 18443:18443 \
    -v $PWD/put-server-conf:/conf \
    --env BPL_JVM_THREAD_COUNT=25 \
    --env JAVA_OPTS="-Dspring.config.location=/conf/application.properties" \
    $DOCKER_IMAGE
