# Interop server packages

Ubuntu 24.04's RADIUS server and client tool packages, with every `.deb` they need on a bare `ubuntu:24.04`, in
`/debs` of an image that runs nothing, with an apt index (`Packages`) — for CI only, never for production. The
`verify` job of `ci.yml` pulls `ghcr.io/radiusward/radiusward-test-images:interop-debs-<hash>`, copies `/debs` out,
uses it as a local apt repository and as apt's archive cache (installing straight from the `file:` source fails
when an essential package is upgraded), so apt resolves against the installed packages, never downgrades them, and
the interop tests (`-Pinterop`) do not need a package mirror. Only when the tag is not published or its packages do
not fit the runner (an installed package newer than the image's) it installs from the mirror as before ([test images](../../docs/testing/strategy.md#test-images)).
amd64 only, like the runners.

```bash
docker create --name debs "ghcr.io/radiusward/radiusward-test-images:$(scripts/test-images.sh tag interop-debs)" none
docker cp debs:/debs /tmp/debs && docker rm debs
echo "deb [trusted=yes] file:/tmp/debs ./" | sudo tee /etc/apt/sources.list.d/interop-debs.list
sudo apt-get update -o Dir::Etc::sourcelist=sources.list.d/interop-debs.list -o Dir::Etc::sourceparts=-
sudo apt-get install -y -o Dir::Cache::archives=/tmp/debs freeradius freeradius-utils
```
