# Local development

Phase 0–1 run entirely on your machine — no Docker ([ADR 0009](../adr/0009-local-first-development.md)).

## Setup (macOS)

```bash
brew install --cask temurin@25              # or any JDK 25+
export JAVA_HOME=$(/usr/libexec/java_home -v 25)
./mvnw verify                                 # first run downloads Maven 3.9.10 via the wrapper
```

Optional:

```bash
brew install freeradius-server                # enables ./mvnw -Pinterop verify
sudo sysctl -w kern.ipc.maxsockbuf=8388608    # larger UDP socket buffers (Aeron warns otherwise, Phase 1)
```

## IntelliJ IDEA

- Open the root `pom.xml` as a project; set the project SDK to 21.
- Run `./mvnw generate-sources` once (or *Generate Sources and Update Folders*) so
  `radius-codec/target/generated-sources/radius` is a source root.
- Add `--add-exports java.base/jdk.internal.misc=ALL-UNNAMED` to the JUnit and Application run
  configuration templates (VM options). Agrona and Aeron need it.
- Install the palantir-java-format plugin, or run `./mvnw spotless:apply` before committing.

## Everyday commands

| Task | Command |
|---|---|
| full build + tests | `./mvnw verify` |
| one module with its dependencies | `./mvnw -pl radius-codec -am verify` |
| format + headers | `./mvnw spotless:apply` |
| refresh fixture packets after editing a fixture | `./mvnw -pl radius-codec -am test -Dtest=VendorFixtureTest -Dfixtures.update=true -Dsurefire.failIfNoSpecifiedTests=false` |
| benchmarks | `./mvnw -Pbench -pl testing/benchmarks -am package -DskipTests && java -jar testing/benchmarks/target/benchmarks.jar` |
| FreeRADIUS interop | `./mvnw -Pinterop verify` |
| update dictionaries | `scripts/update-dictionaries.sh <sha>` |

## Trying the client

```bash
./mvnw -pl tools/radclient -am package -DskipTests
RADCLIENT="java -jar tools/radclient/target/radclient.jar"

$RADCLIENT decode radius-codec/src/test/resources/fixtures/huawei/start.fixture

# against a local FreeRADIUS (radiusd -X with an accounting listener on 1813, secret testing123)
$RADCLIENT acct --server 127.0.0.1:1813 --secret testing123 --status start --session-id s1 --vendor mikrotik
$RADCLIENT replay radius-codec/src/test/resources/fixtures/cisco/stop.fixture --server 127.0.0.1:1813 --secret testing123
```

## A local cluster

Three ways to run the cluster locally: the in-JVM harness used by tests (`LocalCluster`), a single-process dev mode
(`DevCluster`) for the IDE, and `scripts/run-local.sh` with three `cluster-node` JVMs and two gateways on loopback
for the `kill -9` failover demo ([local-cluster.md](local-cluster.md)).
