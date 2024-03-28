Create postgres instance inside docker

```
docker run --name cdoc2-psql -p 5432:5432 -e POSTGRES_DB=cdoc2 -e POSTGRES_PASSWORD=secret -d postgres

docker start cdoc2-psql
docker stop cdoc2-psql
```
#docker rm cdoc2-psql