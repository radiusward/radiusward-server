# eapol_test interop client

`eapol_test` from wpa_supplicant 2.12, built from the release tarball (checksum pinned in the Dockerfile) with TEAP
and EAP-PWD, which the distribution's package lacks, as an independent EAP peer for the gateway's EAP-TLS, PEAP, TTLS
and TEAP — never for production. Built by `EapolTestIT` in the gateway module (Testcontainers); the
test copies a network configuration and certificates into `/work` and runs `eapol_test` once per case against the
gateway on the host (`host.docker.internal`, mapped to the host gateway).

Run by hand:

```bash
docker build -t radiusward-eapol-test testing/eapol-test
docker run --rm -v "$PWD/peap.conf:/work/peap.conf" --add-host host.docker.internal:host-gateway \
    radiusward-eapol-test sh -c 'eapol_test -c peap.conf -a "$(getent hosts host.docker.internal | cut -d" " -f1)" -p 1812 -s secret'
```
