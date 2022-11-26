logstash:
	@docker-compose up --build logstash
.PHONY: logstash

prepare: logstash
.PHONY: prepare

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
