# Releases

Workflow: [.github/workflows/release.yml](../../.github/workflows/release.yml).

| Trigger | Result |
|---|---|
| push to `main` | `ghcr.io/radiusward/radiusward-server:edge` |
| tag `vX.Y.Z-rc.N` | `:X.Y.Z-rc.N`, GitHub pre-release |
| tag `vX.Y.Z` | `:X.Y.Z`, `:X.Y`, `:latest`, GitHub release |

Every image is built for `linux/amd64` and `linux/arm64` with an SBOM and provenance attestation. A release
runs the full build with JDK 25 (bytecode Java 21), unit and end-to-end tests, then publishes the image and
a GitHub Release with `radiusward.jar` and `radclient.jar`. The fault-injection tests (`linux-tests.yml`) run
for the same tag in parallel; check them before announcing a release.

## Cutting a release

1. `main` is green (ci, the latest nightly linux-tests).
2. Update `docs/plans/roadmap.md` and the changelog notes if needed.
3. Tag and push (the version in the poms is set from the tag during the build):

   ```bash
   git tag -a v0.2.0-rc.1 -m "radiusward 0.2.0-rc.1"
   git push origin v0.2.0-rc.1
   ```

4. Check the workflow, the image (`docker run --rm ghcr.io/radiusward/radiusward-server:0.2.0-rc.1 version`)
   and the release page.

The GHCR package is private after its first push; make it public once in the package settings.

## Verifying an image

```bash
docker buildx imagetools inspect ghcr.io/radiusward/radiusward-server:0.2.0-rc.1 --format '{{json .SBOM}}'
docker buildx imagetools inspect ghcr.io/radiusward/radiusward-server:0.2.0-rc.1 --format '{{json .Provenance}}'
```
