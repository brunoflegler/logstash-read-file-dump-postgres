FROM docker.elastic.co/logstash/logstash-oss:7.15.0 as es-core-indexer

USER root

RUN yum update -y
RUN yum -y install zip
RUN shopt -s globstar
RUN zip -d /usr/share/logstash/logstash-core/**/*/log4j-core-2.* org/apache/logging/log4j/core/lookup/JndiLookup.class
RUN chown logstash:logstash /usr/share/logstash/logstash-core/lib/jars/

RUN ["bash", "-c", "logstash-plugin install logstash-integration-kafka"]
RUN ["bash", "-c", "logstash-plugin install logstash-filter-json"]
RUN ["bash", "-c", "logstash-plugin install logstash-filter-mutate"]
RUN ["bash", "-c", "logstash-plugin install logstash-filter-metrics"]
RUN ["bash", "-c", "logstash-plugin install logstash-codec-avro_schema_registry"]
RUN ["bash", "-c", "logstash-plugin install logstash-codec-line"]
RUN ["bash", "-c", "logstash-plugin install logstash-codec-json"]
RUN ["bash", "-c", "logstash-plugin install logstash-codec-rubydebug"]
RUN ["bash", "-c", "logstash-plugin install logstash-filter-json_encode"]

CMD ["logstash"]
