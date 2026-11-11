# Samba AD domain controller for radiusward's LDAP and Netlogon tests (never for production).
FROM debian:bookworm-slim
RUN apt-get -o Acquire::Retries=5 update \
    && DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=5 install -y --no-install-recommends samba samba-ad-provision samba-ad-dc winbind ldb-tools ca-certificates \
    && rm -rf /var/lib/apt/lists/* /etc/samba/smb.conf
COPY start.sh /start.sh
RUN chmod +x /start.sh
# LDAP, LDAPS, endpoint mapper, Netlogon (fixed RPC port range so tests can map it)
EXPOSE 389 636 135 49152-49155
ENTRYPOINT ["/start.sh"]
