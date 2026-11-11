# test-images

`TestImages`: the images that tests run next to radiusward (eapol_test, radsecproxy, Samba AD), taken from the public
package `ghcr.io/radiusward/radiusward-test-images` when the tag of their current inputs is published, built locally
from their Dockerfile otherwise ([docs/testing/strategy.md](../../docs/testing/strategy.md#test-images)).

```java
// ghcr.io/radiusward/radiusward-test-images:radsec-client-<hash>, or a local build of the same inputs
var proxy = new GenericContainer<>(TestImages.image("radsec-client"));
```

- [images.txt](images.txt) lists every image: build context, Dockerfile and the inputs whose content makes the tag's
  hash; `scripts/test-images.sh` reads the same file (`list`, `tag`, `hash`, `inputs`, `platforms`, `ref`,
  `build [--push]`).
- `-Dradiusward.test.images=auto` (default) pulls when published, `build` always builds locally, `pull` fails when
  the tag is missing.
- `.github/workflows/test-images.yml` publishes a tag once, when its inputs change, weekly and on demand.
