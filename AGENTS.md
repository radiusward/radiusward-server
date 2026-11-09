# AGENTS.md

Instructions for coding assistants working in this repository. Humans: see
[CONTRIBUTING.md](CONTRIBUTING.md) — it is the source of truth and this file only summarises it.

## Build and test

```bash
export JAVA_HOME=$(/usr/libexec/java_home -v 25)   # JDK 25 (the baseline since Phase 5.8)
./mvnw spotless:apply verify                        # format, build, all tests, coverage
```

Every JVM that loads Agrona/Aeron needs `--add-exports java.base/jdk.internal.misc=ALL-UNNAMED`.

```bash
./mvnw -Pe2e verify               # end-to-end tests against real processes
scripts/run-local.sh start        # local cluster; see docs/operations/local-cluster.md
scripts/linux-tests.sh            # fault injection in containers (needs Docker; docs/operations/docker.md)
```

## Rules you must follow

- Follow every rule in [CONTRIBUTING.md § Project rules](CONTRIBUTING.md#project-rules), in particular:
  no allocation on the hot path, status codes instead of exceptions for bad input, deterministic cluster
  service, Accounting-Response only after commit, no Hibernate, no Netty, Docker optional for development.
- Never edit `radius-dictionary-freeradius` resources by hand; use `scripts/update-dictionaries.sh`.
- Never commit generated sources (`target/generated-sources`).
- Add tests and update docs in the same change.
- Do not commit, push or open pull requests unless asked; commits carry the maintainer's identity only.
