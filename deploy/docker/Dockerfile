# Copyright 2026 The radiusward Authors
# SPDX-License-Identifier: Apache-2.0
#
# radiusward image (ADR 0015). Build from the repository root after `./mvnw package`:
#   docker build -f deploy/docker/Dockerfile -t radiusward:dev .
FROM eclipse-temurin:25-jre-noble

ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="radiusward" \
      org.opencontainers.image.description="Replicated RADIUS accounting server built on Aeron Cluster" \
      org.opencontainers.image.source="https://github.com/radiusward/radiusward-server" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

RUN groupadd --system --gid 10001 radiusward \
    && useradd --system --uid 10001 --gid radiusward --home-dir /var/lib/radiusward --shell /usr/sbin/nologin radiusward \
    && mkdir -p /opt/radiusward /etc/radiusward/dictionary.d /var/lib/radiusward \
    && chown -R radiusward:radiusward /var/lib/radiusward

COPY distribution/target/radiusward.jar /opt/radiusward/radiusward.jar
COPY deploy/docker/entrypoint.sh /usr/local/bin/radiusward
COPY LICENSE NOTICE THIRD-PARTY-LICENSES.md /opt/radiusward/

USER 10001:10001
WORKDIR /var/lib/radiusward
ENV RADIUSWARD_PROFILE=small
VOLUME ["/var/lib/radiusward"]
EXPOSE 1812/udp 1813/udp 2083/tcp 9090/tcp

ENTRYPOINT ["/usr/local/bin/radiusward"]
CMD ["version"]
