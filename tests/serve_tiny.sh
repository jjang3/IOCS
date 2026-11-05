#!/bin/bash
# Runtime check for a rewritten tiny (after ./iocs.sh tiny build dta sta rewrite link).
# Run where FSGSBASE works (QEMU x86_64, or real x86-64 Linux >= 5.9); Rosetta SIGILLs.
#   docker run --rm --platform linux/amd64 -v "$PWD":/iocs iocs:dev bash tests/serve_tiny.sh
# Pass: with lib/table.so preloaded, tiny binds its port and serves byte-identical files; without
# the table it must not serve (the %gs-relative accesses would hit address 0).
R=${TINY_DIR:-${IOCS_HOME:-/iocs}/result/tiny}; P=${TINY_PORT:-9990}; fail=0   # TINY_DIR: tiny.new + lib/table.so
[ -x "$R/tiny.new" ] && [ -f "$R/lib/table.so" ] || { echo "missing $R/tiny.new or lib/table.so"; exit 2; }
W=$(mktemp -d); cd "$W" && echo "hello from iocs tiny" > index.html && head -c 300000 /dev/urandom > big.bin
( LD_PRELOAD=$R/lib/table.so timeout 120 "$R/tiny.new" $P > /dev/null 2>&1 & )
for _ in $(seq 60); do curl -s -o /dev/null "http://127.0.0.1:$P/" && break; sleep 1; done
got=$(curl -s -m 10 "http://127.0.0.1:$P/index.html"); [ "$got" = "hello from iocs tiny" ] && echo "index: ok" || { echo "index: FAIL"; fail=1; }
curl -s -m 30 -o "$W/b.out" "http://127.0.0.1:$P/big.bin"; cmp -s "$W/b.out" big.bin && echo "big.bin (300000 bytes): identical" || { echo "big.bin: FAIL"; fail=1; }
rows=$(curl -s -m 10 "http://127.0.0.1:$P/" | grep -c '<tr>'); [ "$rows" -ge 2 ] && echo "directory listing: $rows rows" || { echo "listing: FAIL"; fail=1; }
code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$P/nope"); [ "$code" = 404 ] && echo "missing file: 404" || { echo "404: FAIL ($code)"; fail=1; }
ok=0; for i in $(seq 200); do curl -s -m 5 -o /dev/null "http://127.0.0.1:$P/index.html" && ok=$((ok+1)); done; echo "200 sequential requests: $ok ok"; [ $ok -eq 200 ] || fail=1
pkill -f "tiny.new $P"
# Control: without the table the rewritten accesses dereference %gs base 0, so a request must not
# be served (tiny forks per connection: the parent may stay alive while the child dies).
timeout 30 "$R/tiny.new" $((P+1)) > /dev/null 2>&1 & pid=$!; sleep 3
code=$(curl -s -m 5 -o "$W/nt.out" -w '%{http_code}' "http://127.0.0.1:$((P+1))/index.html"); sleep 1
if kill -0 $pid 2>/dev/null; then state="parent still running"; kill $pid; wait $pid 2>/dev/null; else wait $pid; st=$?; state="process exited (status $st)"; fi
if [ "$code" = 200 ] && cmp -s "$W/nt.out" index.html; then echo "without table.so: still serves correctly, FAIL ($state)"; fail=1
else echo "without table.so: request not served (http=$code; $state), redirection is live"; fi
[ $fail -eq 0 ] && echo "serve_tiny: PASS" || echo "serve_tiny: FAIL"; exit $fail
