#!/bin/bash
# Run the pre-built, tested binaries in artifacts/. Needs only Docker: no Binary Ninja, PIN or
# SUTURE. The CPU and kernel must provide FSGSBASE (x86-64 Linux >= 5.9, or the macOS run VM that
# scripts/lib.sh starts; Rosetta does not provide it).
#   artifacts/test.sh tiny     IOCS-rewritten tiny web server, with and without lib/table.so
#                              (runs in ubuntu:22.04, the glibc it was linked against)
#   artifacts/test.sh nginx    original and IOCS-rewritten Nginx 1.3.9, and the IOCS binary
#                              without table.so (runs in iocs-nginx-build:20.04: glibc 2.31,
#                              OpenSSL 1.1; built here from docker/nginx-build.Dockerfile if missing)
# Each artifacts/<name>/EVIDENCE names the recorded run (evidence/) that built and tested it.
. "$(dirname "$0")/../scripts/lib.sh"
use_vm run
d() { docker run --rm --platform linux/amd64 -v "$IOCS_HOME:/iocs" -w /iocs "$@"; }
case ${1:?tiny or nginx} in
  tiny)
    d -e TINY_DIR=/iocs/artifacts/tiny ubuntu:22.04 bash -c \
      'apt-get update -qq >/dev/null && apt-get install -y -qq curl procps >/dev/null && bash tests/serve_tiny.sh' ;;
  nginx)
    docker image inspect iocs-nginx-build:20.04 >/dev/null 2>&1 || \
      docker build -q --platform linux/amd64 -f "$IOCS_HOME/docker/nginx-build.Dockerfile" -t iocs-nginx-build:20.04 "$IOCS_HOME" >/dev/null
    d iocs-nginx-build:20.04 bash benchmarks/nginx/serve_test.sh original artifacts/nginx/nginx.orig || exit 1
    d iocs-nginx-build:20.04 bash benchmarks/nginx/serve_test.sh iocs artifacts/nginx/nginx artifacts/nginx/lib/table.so || exit 1
    if d iocs-nginx-build:20.04 bash benchmarks/nginx/serve_test.sh no-table artifacts/nginx/nginx >/dev/null 2>&1; then
        echo "[no-table] came up without table.so: FAIL"; exit 1
    else echo "[no-table] does not come up without table.so (expected)"; fi ;;
  *) echo "usage: artifacts/test.sh tiny|nginx"; exit 2 ;;
esac
