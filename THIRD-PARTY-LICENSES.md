# Third-party licenses

## Bundled content

| Component | Where | License | Notes |
|---|---|---|---|
| FreeRADIUS RADIUS dictionaries | `radius-dictionary-freeradius` | [CC BY 4.0](radius-dictionary-freeradius/LICENSE-CC-BY-4.0.txt) | Copyright The FreeRADIUS Server project and contributors. Unmodified except the root `dictionary` (one `$INCLUDE` commented out, recorded in its header). Source commit: [`SOURCE.properties`](radius-dictionary-freeradius/src/main/resources/io/radiusward/radius/dictionary/freeradius/SOURCE.properties). Only files carrying the CC BY 4.0 header are bundled; `scripts/update-dictionaries.sh` enforces this. |

## Runtime dependencies

| Dependency | License |
|---|---|
| [Agrona](https://github.com/aeron-io/agrona) | Apache-2.0 |
| [Aeron](https://github.com/aeron-io/aeron) (client, driver, archive, cluster) | Apache-2.0 |
| [Apache Log4j 2](https://logging.apache.org/log4j/2.x/) (api, core) | Apache-2.0 |
| [LMAX Disruptor](https://github.com/LMAX-Exchange/disruptor) 4.x (used by Log4j2 async loggers) | Apache-2.0 |

## Container image

The published image (`deploy/docker/Dockerfile`) is based on
[`eclipse-temurin:25-jre-noble`](https://hub.docker.com/_/eclipse-temurin): the Eclipse Temurin JRE
(GPL-2.0 with Classpath Exception) on Ubuntu 24.04 (packages under their own licenses, listed in the image's
SBOM). radiusward runs on it unmodified.

## Build and test dependencies (not distributed)

| Dependency | License | Use |
|---|---|---|
| JUnit 5 | EPL-2.0 | tests |
| AssertJ | Apache-2.0 | tests |
| jqwik | EPL-2.0 | property-based fuzz tests |
| aaa4j-radius | Apache-2.0 | reference implementation for differential tests |
| SBE (sbe-tool) | Apache-2.0 | code generation for the protocol module; generated code ships, the tool does not |
| JMH | GPL-2.0 with Classpath Exception | benchmarks module only (`-Pbench`), never shipped |
| Testcontainers (with docker-java) | MIT (Apache-2.0) | `testing/linux-tests` only |
| [LazyFS](https://github.com/dsrhaslab/lazyfs) | MIT | built from source into the test image `radiusward-test` (`testing/linux-tests/docker`, with a small `statfs` patch), never published |
| spdlog, toml11 | MIT | LazyFS build dependencies, test image only |
| Spotless, palantir-java-format, JaCoCo, Maven plugins | Apache-2.0 / EPL-2.0 | build tooling |
