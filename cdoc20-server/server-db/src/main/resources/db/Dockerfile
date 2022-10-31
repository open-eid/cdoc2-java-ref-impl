# this file is used to build a docker image for upgrading the database in RIA infra
FROM nexus.riaint.ee:8500/liquibase/liquibase

WORKDIR /liquibase/changelog

COPY changelog/db.changelog-master.yaml ./
# create dir structure as specified in changelog file above
ADD changelog/changes ./db/changelog/changes

COPY liquibase.properties.docker ./liquibase.properties

CMD liquibase --url=$DB_URL --username=$DB_USER --password=${DB_PASSWORD} update
