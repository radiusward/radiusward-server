# Releases

Workflow: [.github/workflows/release.yml](../../.github/workflows/release.yml).

| Trigger | Result |
|---|---|
| push to `main` | `ghcr.io/radiusward/radiusward-server:edge`; the Maven artifacts `X.Y.Z-SNAPSHOT` |
| tag `vX.Y.Z-rc.N` | `:X.Y.Z-rc.N`, Helm chart `X.Y.Z-rc.N`, GitHub pre-release; the Maven artifacts `X.Y.Z-rc.N` |
| tag `vX.Y.Z` | `:X.Y.Z`, `:X.Y`, `:latest`, Helm chart `X.Y.Z`, GitHub release; the Maven artifacts `X.Y.Z` |

Every image is built for `linux/amd64` and `linux/arm64` with an SBOM and provenance attestation. A release
runs the full build with JDK 25, unit and end-to-end tests, then publishes the image, the Helm chart
(`oci://ghcr.io/radiusward/charts/radiusward`, chart and app version equal to the tag, so it installs that image) and
a GitHub Release with `radiusward.jar` and `radclient.jar`. The fault-injection tests (`linux-tests.yml`) run
for the same tag in parallel; check them before announcing a release.

## Maven artifacts

The modules are named `io.radiusward:radiusward-<module>` (e.g. `radiusward-server`, `radiusward-codec`,
`radiusward-auth-api`; the bundled dictionaries are `radiusward-dictionaries`). The `release` profile adds a sources
and a javadoc jar to each published module; every jar carries `META-INF/LICENSE` and `META-INF/NOTICE`. Not
published: `testing/*`, `distribution` (the runnable jars are on the GitHub release) and `radius-codegen` (build time
only). Check locally:

```bash
./mvnw -Prelease,quick install -DskipTests
```

`radiusward-bom` lists the versions of all of them; it has no parent, so importing it pins only radiusward's own
artifacts, not the libraries radiusward builds with (`scripts/tests/test_bom.py` keeps its list equal to the
published modules).

**Publishing.** The `maven` job of `release.yml` deploys them to GitHub Packages
(`https://maven.pkg.github.com/radiusward/radiusward-server`) with the workflow's `GITHUB_TOKEN`: snapshots on every
push to `main`, the release version on a tag (set in every pom, the BOM included, with `versions:set
-DprocessAllModules=true`). It runs after the image job's tests and on its own, so a failed upload never holds up the
image, the chart or the GitHub Release. A version, once published, cannot be published again. Maven Central for
releases follows ([embedded.md](../plans/embedded.md), E7).

**Using them.** GitHub Packages asks for a token even for public packages: a personal access token (classic) with
`read:packages`, in `~/.m2/settings.xml`:

```xml
<settings>
  <servers>
    <server><id>github</id><username>YOUR_GITHUB_USER</username><password>YOUR_TOKEN</password></server>
  </servers>
  <profiles>
    <profile>
      <id>radiusward</id>
      <repositories>
        <repository>
          <id>github</id>
          <url>https://maven.pkg.github.com/radiusward/radiusward-server</url>
          <snapshots><enabled>true</enabled></snapshots>
        </repository>
      </repositories>
    </profile>
  </profiles>
  <activeProfiles><activeProfile>radiusward</activeProfile></activeProfiles>
</settings>
```

With Gradle: `maven { url = uri("https://maven.pkg.github.com/radiusward/radiusward-server"); credentials { username =
providers.gradleProperty("gpr.user").get(); password = providers.gradleProperty("gpr.key").get() } }`.

## Public packages

GitHub creates new organization packages as private. Once per package an organization owner makes it public:
organization **Settings → Packages → Package creation** must allow **Public**, then on the package's page **Package
settings → Change visibility → Public**, and under **Manage Actions access** the `radiusward-server` repository keeps
**Write**. Done for the image `ghcr.io/radiusward/radiusward-server` (2026-11-11); the Helm chart
`oci://ghcr.io/radiusward/charts/radiusward` is public since the first tag (`0.1.0-rc.1`, 2026-11-11). The test-image
package `ghcr.io/radiusward/radiusward-test-images` is public too (2026-11-11,
[test images](../testing/strategy.md#test-images)). Check without
credentials: `DOCKER_CONFIG=$(mktemp -d) docker pull ghcr.io/radiusward/radiusward-server:edge`.

## Cutting a release

1. `main` is green (ci, the latest nightly linux-tests).
2. Update `docs/plans/roadmap.md` if needed; the release notes are generated from the commits.
3. Tag and push (the version in the poms is set from the tag during the build):

   ```bash
   git tag -a v0.2.0-rc.1 -m "radiusward 0.2.0-rc.1"
   git push origin v0.2.0-rc.1
   ```

4. Check the workflow, the image (`docker run --rm ghcr.io/radiusward/radiusward-server:0.2.0-rc.1 version`)
   and the release page.

## Upgrading a cluster

State-machine rules are versioned ([ADR 0005](../adr/0005-log-determinism-versioning.md)); a release may know a newer
version than the cluster applies.

1. Restart the members with the new release **one at a time**, waiting for `/ready` and equal `stateDigest` on all
   members before the next. They keep applying the active version.
2. When the last member runs the new release, the cluster activates the new version by itself (within
   `log.purge.interval`, default 1 min), at the same log position on every member — watch
   `radiusward_state_version{kind="active"}`.
3. To keep a rollback possible, set `cluster.version.hold=true` on the members first; activate later with
   `radiusward admin activate-version --members … --version <n>`. Before activation every member can go back to the
   previous release; after it, a member on an older release stops with "the cluster applies state version n" and
   must be upgraded.
4. RADIUS servers and the exporter need no order: the protocol only appends fields.

## Verifying an image

```bash
docker buildx imagetools inspect ghcr.io/radiusward/radiusward-server:0.2.0-rc.1 --format '{{json .SBOM}}'
docker buildx imagetools inspect ghcr.io/radiusward/radiusward-server:0.2.0-rc.1 --format '{{json .Provenance}}'
```
