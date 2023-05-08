FROM openjdk:17-slim
ARG NAME
WORKDIR /opt/cdoc2

COPY get-server/docker/docker-entrypoint.sh /
COPY get-server/docker/application.properties /opt/cdoc2/
COPY get-server/target/cdoc20-get-server*.jar /opt/cdoc2/${NAME}.jar
COPY keys/servertruststore.jks keys/cdoc20server.p12 /opt/cdoc2/keys/

ENV NAME ${NAME}

ENTRYPOINT ["/docker-entrypoint.sh"]
