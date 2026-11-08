# Vendor captures

The vendor fixtures (`radius-codec/src/test/resources/fixtures/<vendor>/<event>.fixture`) are synthetic until
someone with access to the device captures real packets. A capture turns into a fixture in four steps.

## 1. Capture

On a lab NAS or a mirror port, one Start, one Interim-Update and one Stop of the same session:

```bash
tcpdump -i any -w acct.pcap udp port 1813
```

Extract the RADIUS payload of each Accounting-Request as hex (Wireshark: *Copy → as Hex Stream* on the
RADIUS layer, or `tshark -r acct.pcap -Y 'radius.code == 4' -T fields -e udp.payload`).

## 2. Convert and anonymise

```bash
java -jar tools/radclient/target/radclient.jar decode <hex> --fixture --anonymise \
    --comment "Cisco ASR 1001-X, IOS-XE 17.9.4, PPPoE: interim" > interim.fixture
```

`--fixture` prints the attributes in fixture syntax (dictionary names, `VALUE` names, decimals, dotted
quads, raw strings, `0x...` for everything else). `--anonymise` replaces consistently, so related values
stay related:

| Value | Replacement |
|---|---|
| any IPv4 attribute, and IPv4 addresses inside strings | RFC 5737 documentation addresses (192.0.2.x, 198.51.100.x, 203.0.113.x) |
| MAC addresses inside strings (`aa:bb:..`, `aa-bb-..`, `aabb.ccdd.eeff`) | locally administered `02:00:00:00:00:nn` in the same notation |
| `User-Name` | `user<n>`, realm replaced with `@example.net` |
| attributes missing from the dictionary | dropped (a comment shows vendor and type) |

## 3. Review by hand (required)

`--anonymise` does not understand every vendor format. Check every line for:

- names, phone numbers, account or contract numbers, circuit IDs, location strings (`Called-Station-Id`
  often carries an SSID or site name, `NAS-Identifier` a hostname, Cisco AVPairs a `circuit-id-tag`);
- IPv6 prefixes (`Framed-IPv6-Prefix`, `Delegated-IPv6-Prefix`): replace with `2001:db8::/32` (RFC 3849);
- `0x...` values: binary attributes may embed MAC or IP addresses;
- `Acct-Session-Id` and `Class`: usually opaque, but some vendors embed the subscriber.

Then change the comment's `reviewed: TODO` to who reviewed it.

## 4. Add it

1. Put the file next to the synthetic ones (or replace one) and fill in `expect:` with the hot fields the
   extractor must produce, taken from the vendor documentation, not from our output.
2. Write the `packet:` line (re-signed with the test secret):

   ```bash
   ./mvnw -pl radius-codec -am test -Dtest=VendorFixtureTest -Dfixtures.update=true -Dsurefire.failIfNoSpecifiedTests=false
   ```

3. Run the test again without `-Dfixtures.update` and commit the fixture.
