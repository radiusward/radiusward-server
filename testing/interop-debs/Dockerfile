# Copyright 2026 The radiusward Authors
# SPDX-License-Identifier: Apache-2.0
#
# TEST ONLY: Ubuntu's RADIUS server and client tool packages for the interop tests (-Pinterop) on CI's ubuntu-24.04
# runners, published as ghcr.io/radiusward/radiusward-test-images:interop-debs-<hash>
# (docs/testing/strategy.md#test-images). /debs is a local apt repository with every .deb the two packages need on a
# bare ubuntu:24.04, so the runner installs them without reaching a package mirror; apt resolves against what is
# installed already and never downgrades it. /debs doubles as apt's archive cache: installing from the file: source
# directly fails when an essential package is upgraded ("Pathname to install is not absolute").
#
#   docker create --name debs <image> none && docker cp debs:/debs /tmp/debs
#   echo "deb [trusted=yes] file:/tmp/debs ./" | sudo tee /etc/apt/sources.list.d/interop-debs.list
#   sudo apt-get update -o Dir::Etc::sourcelist=sources.list.d/interop-debs.list -o Dir::Etc::sourceparts=-
#   sudo apt-get install -y -o Dir::Cache::archives=/tmp/debs freeradius freeradius-utils
#
# amd64 only (the runners); the image holds files, it runs nothing.
FROM ubuntu:24.04 AS download
RUN mkdir -p /debs/partial \
    && apt-get -o Acquire::Retries=5 update \
    && DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=5 -o Dir::Cache::archives=/debs \
        install --download-only -y freeradius freeradius-utils \
    && rm -rf /debs/partial /debs/lock \
    && ls /debs/*.deb >/dev/null

# the index in a separate stage, so apt-utils does not shrink the closure above
FROM ubuntu:24.04 AS index
RUN apt-get -o Acquire::Retries=5 update \
    && DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=5 install -y --no-install-recommends apt-utils
COPY --from=download /debs/ /debs/
RUN cd /debs && apt-ftparchive packages . > Packages

FROM scratch
COPY --from=index /debs/ /debs/
