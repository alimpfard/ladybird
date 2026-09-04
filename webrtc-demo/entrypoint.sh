#!/bin/bash
set -euo pipefail
cp /etc/webrtc-demo/janus*.jcfg /etc/janus/
if [[ -n "${PUBLIC_IP:-}" ]]; then
    if [[ ! "$PUBLIC_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo 'PUBLIC_IP must be an IPv4 address' >&2
        exit 1
    fi
    IFS=. read -r -a octets <<< "$PUBLIC_IP"
    for octet in "${octets[@]}"; do
        (( 10#$octet <= 255 )) || { echo 'Invalid PUBLIC_IP' >&2; exit 1; }
    done
    cat >> /etc/janus/janus.jcfg <<NAT
nat: {
    nat_1_1_mapping = "$PUBLIC_IP"
    keep_private_host = false
}
NAT
fi
janus -F /etc/janus &
janus_pid=$!
nginx -c /etc/webrtc-demo/nginx.conf -g 'daemon off;' &
nginx_pid=$!
cleanup() {
    kill "$janus_pid" "$nginx_pid" 2>/dev/null || true
    wait "$janus_pid" "$nginx_pid" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 0' TERM INT
# Restart the container if either essential process exits.
set +e
wait -n "$janus_pid" "$nginx_pid"
status=$?
exit "$status"
