logstash:
	@docker-compose up --build logstash
.PHONY: logstash

localstack:
	@docker-compose up -d localstack
.PHONY: logstash

prepare: localstack logstash
.PHONY: prepare

new-bucket:
	@aws s3 mb --endpoint-url=http://localhost:4566 s3://backups
.PHONY: new-bucket

copy-bucket:
	@aws s3 cp --endpoint-url=http://localhost:4566 config/files/table1.sql s3://backups

stop:
	@docker-compose stop
.PHONY: stop

down:
	@docker-compose down
.PHONY: down

purge-all:
	@docker ps -aq | xargs docker stop
	@docker ps -aq | xargs docker rm
	@docker images -q | xargs docker rmi
.PHONY: purge-all

