#!/bin/sh

DOCKER_IMAGE=harbor.riaint.ee/cdoc2/cdoc20-server-gatling

CONTAINER_NAME=cdoc2-server-gatling-func-tests

docker pull $DOCKER_IMAGE

docker stop $CONTAINER_NAME
docker rm -f $CONTAINER_NAME

docker run -v $PWD/gatling-conf:/conf \
    -e JAVA_OPTS="-Dconfig.file=/conf/application.conf" \
    -e MAIN_CLASS="io.gatling.app.Gatling" \
    -e MAIN_CLASS_ARGS="-s ee.cyber.cdoc20.server.KeyCapsuleFunctionalTests" \
    --name $CONTAINER_NAME $DOCKER_IMAGE
