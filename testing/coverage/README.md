# coverage

Aggregate coverage over unit and integration tests of every module, with a floor per module; only with
`-Pcoverage` (CI's `coverage` job).

```bash
./mvnw -Pcoverage verify -Dradiusward.require.docker=true   # report: testing/coverage/target/site/jacoco-aggregate/
```

- [floors.properties](floors.properties): the minimum line coverage per module (artifactId=ratio) and in total, a few
  points below the measured value. Raise a floor when its module gains tests, never lower it to make a change pass.
- [check-floors.sh](check-floors.sh) compares the aggregate `jacoco.csv` against the floors and fails the build below
  one.
- Integration tests (`*IT`) run without the JaCoCo agent in `./mvnw verify` (allocation measurements); this profile
  adds it, so the numbers include them. `radius-codec` (90 %) and `radius-dictionary` (80 %) have their own floors in
  every `./mvnw verify`.
