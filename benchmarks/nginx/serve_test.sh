#!/bin/bash
# Runtime check for Nginx: serve_test.sh <label> <nginx binary> [table.so to LD_PRELOAD]
# Run in iocs-nginx-build:20.04 (the binary links OpenSSL 1.1) on a daemon with FSGSBASE
# (QEMU x86_64 or real x86-64 Linux >= 5.9; Rosetta SIGILLs on rdgsbase):
#   docker run --rm --platform linux/amd64 -v "$PWD":/iocs iocs-nginx-build:20.04 \
#     bash benchmarks/nginx/serve_test.sh iocs build/nginx/nginx-1.3.9/objs/nginx \
#          build/nginx/nginx-1.3.9/objs/src/lib/table.so
# Pass: byte-identical files of 128 KiB, 1 MiB and 4 MiB, a 404, and an ApacheBench run with no
# failed requests. With no table given, the run only reports whether Nginx came up.
L=$1; BIN=$2; PRE=${3:-}; PORT=${NGINX_PORT:-8080}; N=${AB_N:-2000}; C=${AB_C:-4}
P=$(mktemp -d); W=$P/www; mkdir -p "$P/logs" "$W"
echo "hello from IOCS nginx" > "$W/index.html"
for s in 128 1024 4096; do head -c $((s*1024)) /dev/urandom > "$W/f${s}k.bin"; done
chmod -R a+rX "$P"   # workers run as nobody; mktemp -d is mode 700
cat > "$P/test.conf" <<EOF
worker_processes 1; daemon off; master_process on;
error_log $P/logs/error.log; pid $P/logs/nginx.pid;
events { worker_connections 256; }
http { access_log off; sendfile on; server { listen $PORT; root $W; } }
EOF
if [ -n "$PRE" ]; then LD_PRELOAD=$PRE "$BIN" -p "$P" -c "$P/test.conf" & else "$BIN" -p "$P" -c "$P/test.conf" & fi
pid=$!; up=0; fail=0
for _ in $(seq 120); do curl -s -o /dev/null "http://127.0.0.1:$PORT/" && { up=1; break; }; kill -0 $pid 2>/dev/null || break; sleep 1; done
echo "[$L] up=$up"
if [ $up = 1 ]; then
  [ "$(curl -s "http://127.0.0.1:$PORT/index.html")" = "hello from IOCS nginx" ] && echo "[$L] index: ok" || { echo "[$L] index: FAIL"; fail=1; }
  for f in f128k.bin f1024k.bin f4096k.bin; do
    curl -s -o "$P/$f.got" "http://127.0.0.1:$PORT/$f"
    cmp -s "$P/$f.got" "$W/$f" && echo "[$L] $f identical" || { echo "[$L] $f MISMATCH"; fail=1; }
  done
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/nope"); echo "[$L] 404: $code"; [ "$code" = 404 ] || fail=1
  ab -q -n "$N" -c "$C" "http://127.0.0.1:$PORT/f128k.bin" 2>&1 \
    | grep -E "Complete requests|Failed requests|Non-2xx|Requests per second" | sed "s/^/[$L] ab: /"
  ab -q -n "$N" -c "$C" "http://127.0.0.1:$PORT/f128k.bin" 2>&1 | grep -qE "Failed requests: +0$" || fail=1
  kill -0 $pid 2>/dev/null && echo "[$L] master alive after load" || fail=1
else fail=1; fi
grep -hE "alert|emerg|crit|signal" "$P/logs/error.log" 2>/dev/null | head -3 | sed "s/^/[$L] errlog: /"
kill -QUIT $pid 2>/dev/null; sleep 2; kill -9 $pid 2>/dev/null; wait $pid 2>/dev/null; echo "[$L] exit=$?"
[ $fail -eq 0 ] && echo "[$L] serve_test: PASS" || echo "[$L] serve_test: FAIL"; exit $fail
