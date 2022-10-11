#!/bin/sh

DOCKER_IMAGE=harbor.riaint.ee/cdoc2/cdoc20-server

CONTAINER_NAME=cdoc2-server

docker pull $DOCKER_IMAGE

docker stop $CONTAINER_NAME
docker rm $CONTAINER_NAME

# decrease thread count (default 250) to run on machine with 1 GB RAM
docker run -d --name $CONTAINER_NAME --user "$(id -u):$(id -g)" \
  -p 8443:8443 \
  -v $PWD/conf:/conf \
  --env BPL_JVM_THREAD_COUNT=100 \
  --env JAVA_OPTS="-Dspring.config.location=/conf/application.properties" \
  $DOCKER_IMAGE
