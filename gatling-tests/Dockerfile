# this file is used to build a docker image with cdoc Gatling tests

# for RIA infra
FROM nexus.riaint.ee:8500/library/openjdk:17-alpine

# for non-RIA infra
#FROM openjdk:17-alpine

WORKDIR /gatling

# the gatling .jar file is provided at runtime
ARG JAR_FILE=gatling.jar

COPY ${JAR_FILE} /gatling/gatling-tests.jar

CMD java ${JAVA_OPTS} -cp /gatling/gatling-tests.jar ${MAIN_CLASS} ${MAIN_CLASS_ARGS}

