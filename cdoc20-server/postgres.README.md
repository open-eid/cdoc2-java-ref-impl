Create postgres instance inside docker

```
docker run --name cdoc20-psql -p 5432:5432 -e POSTGRES_DB=cdoc20 -e POSTGRES_PASSWORD=secret -d postgres

docker start cdoc20-psql
docker stop cdoc20-psql
```
#docker rm cdoc20-psql