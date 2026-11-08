# AGENTS.md

Instructions for coding assistants working in this repository. Humans: see
[CONTRIBUTING.md](CONTRIBUTING.md) — it is the source of truth and this file only summarises it.

## Build and test

```bash
export JAVA_HOME=$(/usr/libexec/java_home -v 21)   # JDK 21; CI also runs 25
./mvnw spotless:apply verify                        # format, build, all tests, coverage
```

Every JVM that loads Agrona/Aeron needs `--add-exports java.base/jdk.internal.misc=ALL-UNNAMED`.

## Rules you must follow

- Follow every rule in [CONTRIBUTING.md § Project rules](CONTRIBUTING.md#project-rules), in particular:
  no allocation on the hot path, status codes instead of exceptions for bad input, deterministic cluster
  service, Accounting-Response only after commit, no Hibernate, no Netty, no Docker in Phase 0–1.
- Never edit `radius-dictionary-freeradius` resources by hand; use `scripts/update-dictionaries.sh`.
- Never commit generated sources (`target/generated-sources`).
- Add tests and update docs in the same change.
- Do not commit, push or open pull requests unless asked; commits carry the maintainer's identity only.
