#!/bin/bash
# Nginx 1.3.9 end to end with the canonical pipeline, recording the evidence.
#   scripts/run_nginx.sh
#   build VM: build   benchmarks/nginx/build_nginx.sh in iocs-nginx-build:20.04 (gcc 9.4, glibc 2.31)
#   build VM: patch   benchmarks/nginx/nginx.sh nginx patch in iocs:dev (Binary Ninja + rewriter, --directory)
#   build VM: relink  Nginx's own make in iocs-nginx-build:20.04 (must recompile nothing)
#   run VM:   serve   benchmarks/nginx/serve_test.sh: original binary (control), IOCS binary with table.so,
#                     IOCS binary without table.so (must not come up)
# DTA is not re-run for Nginx: the function list is the committed benchmarks/nginx/nginx.analysis.
# Every analysis (SUTURE's entry config, the tree rewrite's DWARF and Binary Ninja) reads
# build/nginx/nginx.orig, the binary as built, never objs/nginx (rewritten after a relink).
# Tree mode: STEPS (default "build sta patch serve") runs only some steps; SUTURE on Nginx takes
# hours, so "build sta" can run first and "patch serve" (which reuses its results) later.
# Evidence: evidence/nginx/<UTC stamp>/ (env.txt, per-step logs, summary.txt, patch-sites.txt,
# sha256.txt, table.c).
. "$(dirname "$0")/lib.sh"
NG_REL=build/nginx/nginx-$NGINX_VERSION; NG=/iocs/$NG_REL; HNG=$IOCS_HOME/$NG_REL
# IOCS_REWRITE_MODE=tree: src/ptr_offset_tree (SUTURE-tainted variables + pointer offset trees);
# default directory mode rewrites every local of the DTA-traced functions.
MODE=${IOCS_REWRITE_MODE:-directory}
NGRES=build/tree/result/nginx            # tree mode: SUTURE inputs, nginx.bc, trees.txt, table.c
name=nginx; [ "$MODE" = directory ] || name=nginx-$MODE
evidence_start "$name"
STEPS=" ${STEPS:-build sta patch serve} "; step() { [ "$MODE" != tree ] || case $STEPS in *" $1 "*) return 0 ;; *) return 1 ;; esac; }
echo "steps:      ${STEPS# }" >> "$EVID/env.txt"
use_vm build; ev_images
step build && ev_run 1-build  in_image iocs-nginx-build:20.04 bash -c "INTEL=1 bash benchmarks/nginx/build_nginx.sh && cp $NG/objs/nginx /iocs/build/nginx/nginx.orig"
if [ "$MODE" = tree ]; then
    # One bitcode module (dev: SUTURE's clang 9), link it (suture image: has llvm-link), then
    # SUTURE on it with every DTA function's parameters as taint sources, then the tree rewrite.
    if step sta; then
        ev_run 2a-bitcode in_image iocs:dev            env NGINX_HOME=$NG IOCS_RESULT_DIR=/iocs/build/tree/result bash benchmarks/nginx/nginx.sh nginx bitcode
        ev_run 2b-bclink  in_image iocs-suture:llvm9   env NGINX_HOME=$NG IOCS_RESULT_DIR=/iocs/build/tree/result bash benchmarks/nginx/nginx.sh nginx bclink
        # (NGINX_STA=whole: one SUTURE run of every entry, days; default: one run per entry, each
        # with SUTURE_ENTRY_TIMEOUT, benchmarks/nginx/suture_split.sh)
        ev_run 2c-sta     in_image iocs:dev            env NGINX_HOME=$NG IOCS_RESULT_DIR=/iocs/build/tree/result SUTURE_TIMEOUT=${SUTURE_TIMEOUT:-86400} \
            SUTURE_ENTRY_TIMEOUT=${SUTURE_ENTRY_TIMEOUT:-1200} SUTURE_JOBS=${SUTURE_JOBS:-6} \
            bash benchmarks/nginx/nginx.sh nginx "$([ "${NGINX_STA:-split}" = whole ] && echo sta || echo sta_split)"
        cp "$IOCS_HOME/$NGRES/suture-entries.txt" "$EVID/" 2>/dev/null || true
    else
        echo "sta not run (STEPS): SUTURE results of $NGRES, nginx.taint from $(date -u -r "$IOCS_HOME/$NGRES/nginx.taint" +%FT%TZ)" > "$EVID/2c-sta.log"
    fi
    step patch || { ev_finalize; say "done (steps:$STEPS): ${EVID#$IOCS_HOME/}"; exit 0; }
    ev_run 2-patch    in_image iocs:dev            env NGINX_HOME=$NG IOCS_RESULT_DIR=/iocs/build/tree/result IOCS_REWRITE_MODE=tree bash benchmarks/nginx/nginx.sh nginx patch
else
    ev_run 2-patch  in_image iocs:dev env NGINX_HOME=$NG bash benchmarks/nginx/nginx.sh nginx patch
fi
# table.so is built again here, in the image Nginx runs in: table.c (per-thread and per-handler
# page sets: pthread_create, dlsym) linked in iocs:dev needs glibc 2.34 symbols, and Nginx runs
# with glibc 2.31.
relink="cd $NG && make && make install && cd objs/src && make -s lib"
ev_run 3-relink in_image iocs-nginx-build:20.04 bash -c "$relink"
recompiled=$(sed 1d "$EVID/3-relink.log" | grep -cE '^(cc|gcc) (.* )?-c ' || true)   # skip ev_run's command header
S=$HNG/objs/src
for f in $(cd "$S" && find . -name '*.s' | sort); do
    read -r r s <<< "$(bash "$IOCS_HOME/scripts/count_sites.sh" "$S/$f")"; [ "$((r + s))" -gt 0 ] && echo "$r $s ${f#./}"
done > "$EVID/patch-sites.txt"   # redirected, syncs, file
ev_summary "nginx:             $NGINX_VERSION (sha256 $NGINX_SHA256)"
if [ "$MODE" = tree ]; then   # (the slots the rewritten code uses; table.c may hold a padding slot too)
    ev_summary "compartments:      $(head -1 "$IOCS_HOME/$NGRES/compartments.txt" | sed 's/^compartments: //')"
    ev_summary "table:             $(sed -n 2p "$IOCS_HOME/$NGRES/compartments.txt")"
    ev_summary "lifts:             $(grep -c '^lifted:' "$IOCS_HOME/$NGRES/lifted.txt" || true) lifted, $(grep -c '^own slot:' "$IOCS_HOME/$NGRES/lifted.txt" || true) kept in their own slot (lifted.txt)"
else
ev_summary "compartments:      $(grep -oE 'malloc\(sizeof\(void\*\) *\* *[0-9]+\)' "$S/table.c" | grep -oE '[0-9]+\)$' | tr -d ')')"
fi
ev_summary "redirected sites:  $(awk '{s+=$1} END {print s+0}' "$EVID/patch-sites.txt") in $(wc -l < "$EVID/patch-sites.txt" | tr -d ' ') files (patch-sites.txt)"
ev_summary "sync copies:       $(awk '{s+=$2} END {print s+0}' "$EVID/patch-sites.txt") (lea_store_gs, stack -> page)"
ev_summary "relink:            $recompiled C files recompiled (must be 0)"
cp "$S/table.c" "$EVID/table.c"
if [ "$MODE" = tree ]; then
    for f in trees.txt lifted.txt compartments.txt nginx.config nginx.vuln suture-entries.txt; do
        [ -f "$IOCS_HOME/$NGRES/$f" ] && cp "$IOCS_HOME/$NGRES/$f" "$EVID/$f"; done
    sed 's/\x1b\[[0-9;]*m//g' "$EVID/2-patch.log"* 2>/dev/null | sed -n 's/.*consistency: \([^ ]*\): \([^ ]*\) stays on the stack (\([^:]*\):.*/\1 \2 \3/p' | sort -u > "$EVID/kept-on-stack.txt"
fi
ev_sites "$S" "$EVID/rewritten-sites.txt"
( cd "$IOCS_HOME" && shasum -a 256 build/nginx/nginx.orig "$NG_REL/objs/nginx" "$NG_REL/objs/src/table.c" "$NG_REL/objs/src/lib/table.so" ) > "$EVID/sha256.txt"
use_vm run; ev_images
ok=1
ev_run 4-serve-original in_image iocs-nginx-build:20.04 bash benchmarks/nginx/serve_test.sh original build/nginx/nginx.orig || ok=0
ev_run 5-serve-iocs     in_image iocs-nginx-build:20.04 bash benchmarks/nginx/serve_test.sh iocs "$NG/objs/nginx" "$NG/objs/src/lib/table.so" || ok=0
if ev_run 6-serve-no-table in_image iocs-nginx-build:20.04 bash benchmarks/nginx/serve_test.sh no-table "$NG/objs/nginx"; then
    ok=0; ev_summary "control:           IOCS binary came up WITHOUT table.so (redirection not live?)"
else ev_summary "control:           IOCS binary does not come up without table.so (expected)"; fi
ev_summary "runtime original:  $(grep -o 'serve_test: [A-Z]*' "$EVID/4-serve-original.log")"
ev_summary "runtime iocs:      $(grep -o 'serve_test: [A-Z]*' "$EVID/5-serve-iocs.log"); $(grep -h 'ab: Failed requests' "$EVID/5-serve-iocs.log" | head -1 | sed 's/.*ab: //')"
[ $recompiled -eq 0 ] || ok=0
ev_finalize
[ $ok = 1 ] && ev_summary "result:            PASS" || { ev_summary "result:            FAIL"; exit 1; }
say "done: ${EVID#$IOCS_HOME/}/summary.txt"
