# embedded

`radiusward-embedded`: radiusward inside a JVM for development and tests ([ADR 0068](../docs/adr/0068-embedded-radiusward-and-maven-central.md),
[plan](../docs/plans/embedded.md)). One cluster member and one RADIUS server by default, or a whole cluster of three
members and several RADIUS servers, started with the same code and settings
as in production, the developer's own identity stores, credential verifiers and sinks, ports chosen at start,
everything gone on `close()`.

**Not for production**: all members share one machine and nothing is synced to disk; it says so in the log at start.

```java
try (EmbeddedRadiusward radius = EmbeddedRadiusward.builder()
                .user("alice", "secret", "Class := gold")           // or identityStore(new MyUsers())
                .start();
        RadiusClient auth = radius.client();
        RadiusClient acct = radius.accountingClient()) {
    auth.pap("alice", "secret");                                      // Access-Accept with Class
    AccountingSession s = new AccountingSession("s-1").user("alice");
    acct.send(s.start());                                             // acknowledged after the commit
    radius.session("s-1");                                            // what the cluster holds
    radius.awaitAccounting(1);                                        // what a sink received
}
```

The JVM needs `--add-exports java.base/jdk.internal.misc=ALL-UNNAMED` (Agrona and Aeron): Surefire's or Failsafe's
`argLine`, Gradle's `jvmArgs`, the IDE's run configuration. `start()` fails with that text when it is missing.
[`testing/embedded-consumer`](../testing/embedded-consumer) is a complete Maven project that uses it.

## Builder

| Method | What it does |
|---|---|
| `user(name, password, replyItems...)` | a user with a password; reply items in the users-file syntax (`"Class := gold"`); PAP, CHAP, MS-CHAP and EAP work with it |
| `identityStore(store)`, `users(name -> Optional<UserRecord>)` | the developer's own store (`auth-api`), asked after the users above, in order |
| `credentialVerifier(verifier)` | checks the passwords of their stores' users that hold none (as an LDAP bind) |
| `sink(sink)`, `sink(name, sink)` | the developer's own sink (`export-api`), with the contract production sinks have; `AccountingSink.of(batch -> ...)` makes one from a function |
| `onAccounting(event -> ...)` | every committed accounting event, in commit order |
| `client(address, secret)`, `client(name, address, secret)` | NAS entries; without any, `local` is 127.0.0.1 with `testing123` |
| `authPort(port)`, `accountingPort(port)` | fixed ports instead of free ones |
| `directory(path)` | keep the files there (not deleted on close) instead of a temporary directory |
| `members(n)`, `radiusServers(n)` | a cluster of 3 (or 5, 7) members and several RADIUS servers, each with its own ports; even numbers of members are refused |
| `eap(methods...)` | EAP methods to offer (`peap`, `ttls`, `teap`, `tls`, `pwd`, `sim`, `aka`, `aka-prime`, `md5`); with a TLS-based one and no certificate of your own, a throwaway CA signs the server's certificate |
| `simUser(imsi, ki, opc, replyItems...)` | a SIM subscriber for EAP-SIM, EAP-AKA and EAP-AKA′; sequence numbers from the cluster |
| `coaPort(port)` | where the NAS entries listen for CoA and Disconnect-Requests (e.g. a `CoaListener`) |
| `setting(key, value)` | any key of [configuration.md](../docs/configuration.md); it overrides the methods above. Unknown keys are ignored, as in a configuration file |

The developer's stores, verifier and sinks run through the same plug-in APIs as in a cluster (`IdentityStoreProvider.of`
and friends, E3), so a class written for a test runs unchanged as a plug-in. They are closed once, on `close()`.

## Running server

| Method | What it does |
|---|---|
| `authPort()`, `accountingPort()`, `host()` | where to send requests |
| `client()`, `accountingClient()` | a `RadiusClient` of either port with the first NAS entry's secret |
| `accounting()`, `awaitAccounting(n)` | the committed events, as every sink gets them |
| `session(acctSessionId)`, `session(nas, acctSessionId)`, `activeSessions(user)` | the replicated state, as the CoA API reads it |
| `authPort(i)`, `accountingPort(i)`, `client(i)`, `server(i)` | the same for RADIUS server `i` |
| `stopMember(i)`, `startMember(i)`, `stopLeader()`, `leader()`, `awaitLeader()` | members stop by closing (a crash is what the process-based e2e tests cover); with three, losing one keeps acknowledging, losing two stops it until one is back |
| `stopServer(i)`, `startServer(i)` | a RADIUS server goes away and comes back on the same ports |
| `ca()`, `clientCertificate(name)` | the throwaway CA for `EapLogin.trust(...)`, and EAP-TLS client certificates it signs |
| `coa(user, items...)`, `disconnect(user)` | CoA and Disconnect-Requests to the NAS of each of the user's active sessions, through the server's CoA path; the NAS's answers as `CoaResult` |
| `pauseCluster()`, `resumeCluster()` | stops and restarts every member: no Accounting-Response meanwhile, the NAS has to resend; what it resends is applied once |
| `server()`, `member()`, `config()` | the RADIUS server, the member and the settings, for everything else |

## EAP

```java
try (EmbeddedRadiusward radius = EmbeddedRadiusward.builder()
                .eap("peap", "tls", "aka")
                .user("alice", "secret", "Class := gold")
                .simUser("262011000000001", ki, opc)
                .start();
        RadiusClient nas = radius.client()) {
    nas.eap(EapLogin.peap("alice", "secret").trust(radius.ca()));
    ClientCertificate laptop = radius.clientCertificate("laptop-1");
    nas.eap(EapLogin.tls("laptop-1", laptop.key(), laptop.certificate()).trust(radius.ca()));
    nas.eap(EapLogin.aka(new SimCard("262011000000001", ki, opc)));
}
```

The throwaway CA, the server's certificate and its key are PEM files in the directory, valid for a day, set as
`auth.eap.tls.certificate`, `.key` and `.ca`; a certificate of your own in those settings replaces them. It uses
Bouncy Castle (`bcpkix`), which `radiusward-embedded` depends on; the server itself does not.

## Defaults

Everything the builder sets is an ordinary setting, overridable with `setting(...)`: a member of one with fsync off
(`archive.file.sync.level=0`), 8 MB archive segments, 10 000 sessions, the newest state version active from the start
(`log.purge.interval=1s`), `auth.reject.delay=0s`, listening on 127.0.0.1 with free ports. Several instances run in
one JVM side by side, each with its own directory and ports.

## Footprint

`FootprintIT` measures it (Apple M-series, JDK 25): about 1.1 s to start with the classes loaded, 30 MB of heap,
10 MB of direct buffers, the process's resident memory 170 MB larger, about 200 MB of files in its directory. Aeron's
memory-mapped files (term buffers, counters) reserve more address space than that; only what is touched becomes
resident.
