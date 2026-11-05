#!/bin/bash
# DTA exercise hook for tiny (used by ./iocs.sh tiny dta).
# The original request mix used for the paper was not recorded; this sends one GET.
# tiny never flushes stdout, so readiness is detected by polling its port (default 9999).
port=${TINY_PORT:-9999}
# IOCS_DTA_PID (set by iocs.sh) is PIN's pid: give up as soon as PIN has exited.
alive() { [ -z "${IOCS_DTA_PID:-}" ] || kill -0 "$IOCS_DTA_PID" 2>/dev/null; }
for _ in $(seq 600); do
    curl -s -o /dev/null "http://127.0.0.1:$port/" && break
    alive || { echo "PIN exited before tiny came up" >&2; exit 1; }
    sleep 1
done
curl -s -o /dev/null "http://127.0.0.1:$port/" || { echo "tiny did not come up on $port" >&2; exit 1; }
sleep 2
