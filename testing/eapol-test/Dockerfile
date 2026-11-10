# eapol_test from wpa_supplicant for radiusward's EAP interop tests (never for production). Built from the
# wpa_supplicant release (pinned by checksum) because the distribution's build has no TEAP.
FROM debian:trixie-slim AS build
ARG WPA_VERSION=2.12
ARG WPA_SHA256=08e23937e16d0155e55cab2b51f51fbe10d80a1aa91c4e15442645059b737ef6
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential pkg-config libssl-dev curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN curl -fsSL -o wpa.tar.gz "https://w1.fi/releases/wpa_supplicant-${WPA_VERSION}.tar.gz" \
    && echo "${WPA_SHA256}  wpa.tar.gz" | sha256sum -c - \
    && tar xzf wpa.tar.gz \
    && cd "wpa_supplicant-${WPA_VERSION}/wpa_supplicant" \
    && printf '%s\n' CONFIG_EAPOL_TEST=y CONFIG_IEEE8021X_EAPOL=y CONFIG_TLS=openssl CONFIG_TLSV12=y \
        CONFIG_EAP_MD5=y CONFIG_EAP_MSCHAPV2=y CONFIG_EAP_TLS=y CONFIG_EAP_PEAP=y CONFIG_EAP_TTLS=y CONFIG_EAP_GTC=y \
        CONFIG_EAP_TEAP=y CONFIG_EAP_PWD=y \
        CONFIG_EAP_SIM=y CONFIG_EAP_AKA=y CONFIG_EAP_AKA_PRIME=y CONFIG_SIM_SIMULATOR=y CONFIG_USIM_SIMULATOR=y \
        > .config \
    && make -j"$(nproc)" eapol_test \
    && install -m 0755 eapol_test /usr/local/bin/eapol_test

FROM debian:trixie-slim
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libssl3t64 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/bin/eapol_test /usr/local/bin/eapol_test
WORKDIR /work
CMD ["sleep", "infinity"]
