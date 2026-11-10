# RadSec interop client

radsecproxy 1.11 with FreeRADIUS's `radclient` and wpa_supplicant's `eapol_test` (Debian packages) as an independent
RadSec client for the gateway, never for production. Built by `RadsecproxyIT` in the gateway module (Testcontainers):
the test copies a radsecproxy configuration and a client certificate into `/work`, starts radsecproxy, and sends
over UDP to it on `127.0.0.1:1812`; radsecproxy forwards over TLS to the gateway on the host
(`host.docker.internal`, mapped to the host gateway). Its log ends up in `gateway/target/radsec-client`.

A second radsecproxy instance in the same container listens on `127.0.0.1:1912` and forwards over DTLS 1.2
(RFC 7360) to the gateway's DTLS port with the secret `radius/dtls`; its log is `radsecproxy-dtls.log`.

`ProxyRadsecproxyIT` uses the same image the other way round: radsecproxy as a RadSec server (TLS on 2083, mapped by
Testcontainers) relaying the gateway's proxied requests over UDP to a fake home server on the host.
