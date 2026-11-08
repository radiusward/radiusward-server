# distribution

Builds the single runnable `distribution/target/radiusward.jar` (shaded, `Add-Exports` in the manifest, so
no JVM flags are needed):

```bash
java -jar radiusward.jar cluster-node --config <file> [--config <file>]...
java -jar radiusward.jar gateway      --config <file> [--config <file>]...
java -jar radiusward.jar cluster-tool <cluster-dir> describe|snapshot|...   # Aeron ClusterTool
java -jar radiusward.jar version
```

In Phase 2 this jar becomes the container image with the same entrypoints.
