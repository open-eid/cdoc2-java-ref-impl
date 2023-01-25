#!/bin/sh

DOCKER_IMAGE=harbor.riaint.ee/cdoc2/cdoc20-server-gatling

CONTAINER_NAME=cdoc2-server-gatling-generate-keystores

docker pull $DOCKER_IMAGE

docker stop $CONTAINER_NAME
docker rm -f $CONTAINER_NAME

NUM_OF_KEYSTORES=4

JAVA_OPTS="-Doutput-dir=/conf/client-keystores -Dkeystore-password=secret -Dkey-alias=client-key"
JAVA_OPTS="${JAVA_OPTS} -Droot-keystore=/conf/gatling-ca.p12 -Droot-keystore-password=secret"
JAVA_OPTS="${JAVA_OPTS} -Droot-key-alias=gatling-ca -Damount=${NUM_OF_KEYSTORES}"

docker run --user "$(id -u):$(id -g)" \
    -v $PWD/gatling-conf:/conf \
    -e JAVA_OPTS="${JAVA_OPTS}" \
    -e MAIN_CLASS="ee.cyber.cdoc20.server.datagen.KeyStoreGenerator" \
    -e MAIN_CLASS_ARGS="" \
    --name $CONTAINER_NAME $DOCKER_IMAGE
