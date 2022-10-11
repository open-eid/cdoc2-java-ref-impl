#!/bin/sh

DOCKER_IMAGE=harbor.riaint.ee/cdoc2/cdoc20-server-liquibase

docker pull $DOCKER_IMAGE

docker run --rm -e DB_URL="jdbc:postgresql://host:5432/db?sslmode=require" -e DB_USER="user" -e DB_PASSWORD="pass" $DOCKER_IMAGE

