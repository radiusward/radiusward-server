# distribution

Builds the single runnable `distribution/target/radiusward.jar` (shaded, `Add-Exports` in the manifest, so
no JVM flags are needed):

```bash
java -jar radiusward.jar cluster-node --config <file> [--config <file>]...
java -jar radiusward.jar gateway      --config <file> [--config <file>]...
java -jar radiusward.jar cluster-tool <cluster-dir> describe|snapshot|...   # Aeron ClusterTool
java -jar radiusward.jar radclient acct|replay|decode|load ...             # test client (tools/radclient)
java -jar radiusward.jar admin state|verify-acks --members ...            # replicated state (tools/admin-cli)
java -jar radiusward.jar probe http://127.0.0.1:9090/ready                # exit 0 on HTTP 200; health checks
java -jar radiusward.jar version
```

The container image (`deploy/docker`, [ADR 0015](../docs/adr/0015-container-image.md)) runs this jar with the
same subcommands: `docker run radiusward:dev cluster-node --config ...`.
