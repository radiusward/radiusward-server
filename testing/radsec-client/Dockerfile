# An independent RadSec client for radiusward's tests (never for production): radsecproxy forwards what radclient
# and eapol_test send over UDP to the gateway over TLS (RFC 6614).
FROM debian:trixie-slim
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends radsecproxy freeradius-utils eapoltest ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
CMD ["sleep", "infinity"]
