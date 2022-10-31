#!/bin/sh

DOCKER_IMAGE=harbor.riaint.ee/cdoc2/cdoc20-get-server

CONTAINER_NAME=cdoc20-get-server

docker pull $DOCKER_IMAGE

docker stop $CONTAINER_NAME
docker rm -f $CONTAINER_NAME

# decrease thread count (default 250) to run on machine with 1 GB RAM
docker run -d --restart unless-stopped --name $CONTAINER_NAME --user "$(id -u):$(id -g)" \
	-p 8444:8444 \
	-v $PWD/get-server-conf:/conf \
       	--env BPL_JVM_THREAD_COUNT=25 \
      	--env JAVA_OPTS="-Dspring.config.location=/conf/application.properties" \
       	$DOCKER_IMAGE

