# benchmarks

JMH benchmarks for the accounting hot path. Not part of the default build.

```bash
./mvnw -Pbench -pl testing/benchmarks -am package -DskipTests
java -jar testing/benchmarks/target/benchmarks.jar                 # all
java -jar testing/benchmarks/target/benchmarks.jar fullReceivePath -prof gc
```

Baseline numbers and how to compare runs: [docs/testing/strategy.md](../../docs/testing/strategy.md).
