#!/bin/sh
# Provisions the test domain CORP.TEST on first start, adds the test accounts, runs Samba in the foreground.
set -e
PASS='Adm1n-Passw0rd!'
if [ ! -f /var/lib/samba/private/sam.ldb ]; then
    samba-tool domain provision --realm=CORP.TEST --domain=CORP --server-role=dc \
        --dns-backend=SAMBA_INTERNAL --adminpass="$PASS" --use-rfc2307 \
        --option="rpc server dynamic port range = 49152-49155" >/dev/null
    samba-tool user create alice 'Alice-Passw0rd!' --given-name=Alice >/dev/null
    samba-tool user create bob 'Bob-Passw0rd!' >/dev/null
    samba-tool user create carol 'Carol-Passw0rd!' >/dev/null
    samba-tool user disable carol >/dev/null
    samba-tool user create svc-radius 'Svc-Passw0rd!' >/dev/null
    samba-tool group add 'VPN Users' >/dev/null
    samba-tool group addmembers 'VPN Users' alice >/dev/null
    samba-tool group add 'Staff' >/dev/null
    samba-tool group addmembers 'Staff' alice,bob >/dev/null
    samba-tool group add 'Remote Workers' >/dev/null
    samba-tool group addmembers 'Remote Workers' 'VPN Users' >/dev/null
    samba-tool computer create RADIUSWARD >/dev/null
    samba-tool user setpassword 'RADIUSWARD$' --newpassword='Machine-Passw0rd-1234567890' >/dev/null
fi
echo "samba-ad provisioned"
exec samba -i --debug-stdout -d "${SAMBA_DEBUG:-1}"
