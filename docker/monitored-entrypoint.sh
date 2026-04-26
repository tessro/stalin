#!/bin/sh
set -eu

if [ -f /srv/cacert.pem ]; then
    cp /srv/cacert.pem /usr/local/share/ca-certificates/local-proxy-ca.crt
    update-ca-certificates >/dev/null
else
    echo "warning: /srv/cacert.pem is not mounted; MITM TLS will not be trusted" >&2
fi

exec "$@"
