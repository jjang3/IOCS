#!/bin/bash
# GNU coreutils 8.31 through the IOCS pipeline (paper Table 1), recording the evidence.
#   scripts/run_coreutils.sh [utility...]      default: basename pwd wc cp factor ls
# Steps and where they run (macOS: VMs switched automatically; Linux: one daemon):
#   build VM: build     benchmarks/coreutils/build_coreutils.sh (20.04 image), once per tree
#   build VM: migrate   result/<u>/ with the program, its objects' .s/.o/.intel (20.04 image)
#   build VM: bitcode   clang 9 bitcode of src/<u>.c for SUTURE (iocs:dev)
#   run VM:   dta       PIN with the workload in benchmarks/coreutils/<u>.dta.args (iocs:dev)
#   build VM: sta       SUTURE entry config, SUTURE, hybrid report (iocs:dev)
#   build VM: rewrite   every object of the program, in --directory mode (iocs:dev, Binary Ninja)
#   build VM: link      objects back into the tree, relink, lib/table.so (20.04 image)
#   run VM:   check     original vs rewritten on the workload, and without table.so (20.04 image)
# Evidence: evidence/coreutils/<UTC stamp>/: env.txt, per-step logs, table1.txt, per utility the
# hybrid report, table.c, rewritten-sites.txt and check.txt.
# IOCS_REWRITE_MODE=tree: the pointer offset tree rewriter (src/ptr_offset_tree) instead, the same
# steps from a clean checkout into build/tree/result/<u>/ (result/ is not touched): bitcode of
# every object of the program, llvm-linked (iocs-suture:llvm9), DTA, STA + SUTURE, tree rewrite,
# link, check, counts. Evidence: evidence/coreutils-tree/<UTC stamp>/, per utility also trees.txt,
# lifted.txt (lifts and the slots kept), compartments.txt (slots the rewritten code uses).
. "$(dirname "$0")/lib.sh"
UTILS=("$@"); [ ${#UTILS[@]} -gt 0 ] || UTILS=(basename pwd wc cp factor ls)
MODE=${IOCS_REWRITE_MODE:-directory}
case $MODE in directory|tree) ;; *) die "IOCS_REWRITE_MODE must be directory or tree" ;; esac
RES=result; EVNAME=coreutils; [ "$MODE" = tree ] && { RES=build/tree/result; EVNAME=coreutils-tree; }
CU=/iocs/build/coreutils/coreutils-$COREUTILS_VERSION
HCU=$IOCS_HOME/build/coreutils/coreutils-$COREUTILS_VERSION
C() { in_image iocs-nginx-build:20.04 env COREUTILS_HOME=$CU IOCS_RESULT_DIR=/iocs/$RES bash benchmarks/coreutils/coreutils.sh "$@"; }
D() { in_image iocs:dev env COREUTILS_HOME=$CU IOCS_RESULT_DIR=/iocs/$RES IOCS_TARGET_DIR=/iocs/benchmarks/coreutils "$@"; }
for u in "${UTILS[@]}"; do
    [ -f "$IOCS_HOME/benchmarks/coreutils/$u.dta.args" ] || die "no workload benchmarks/coreutils/$u.dta.args"
    if [ -d "$IOCS_HOME/$RES/$u" ]; then mkdir -p "$IOCS_HOME/build/old"; mv "$IOCS_HOME/$RES/$u" "$IOCS_HOME/build/old/${RES//\//-}-$u-$(date -u +%Y%m%dT%H%M%SZ)"; fi
done
mkdir -p "$IOCS_HOME/$RES"
evidence_start $EVNAME
echo "mode:       $MODE (results in $RES)" >> "$EVID/env.txt"
use_vm build; ev_images
if [ -x "$HCU/src/ls" ] && [ -f "$HCU/src/ls.s.orig" ] && [ -f "$HCU/src/ls.intel" ]; then
    say "coreutils tree present: $HCU"; echo "coreutils tree already built (not rebuilt)" > "$EVID/1-build.log"
else
    ev_run 1-build in_image iocs-nginx-build:20.04 bash benchmarks/coreutils/build_coreutils.sh
fi
ev_run 2-tools  D ./iocs.sh "${UTILS[0]}" tools
for u in "${UTILS[@]}"; do
    ev_run "3-migrate-$u" C "$u" migrate
    if [ "$MODE" = tree ]; then
        # (every object: the trees and SUTURE's taints cross object boundaries, e.g. cp's six)
        ev_run "4-bitcode-$u" in_image iocs-suture:llvm9 env COREUTILS_HOME=$CU IOCS_RESULT_DIR=/iocs/$RES BITCODE_OBJECTS=1 \
            bash benchmarks/coreutils/coreutils.sh "$u" bitcode
    else ev_run "4-bitcode-$u" D bash benchmarks/coreutils/coreutils.sh "$u" bitcode; fi
done
use_vm run; ev_images
for u in "${UTILS[@]}"; do ev_run "5-dta-$u" D ./iocs.sh "$u" dta; done
use_vm build
failed=()
for u in "${UTILS[@]}"; do
    ev_run "6-sta-$u"     D ./iocs.sh "$u" sta     || { failed+=("$u:sta"); continue; }
    ev_run "7-rewrite-$u" D env IOCS_REWRITE_MODE=$MODE ./iocs.sh "$u" rewrite || { failed+=("$u:rewrite"); continue; }
    ev_run "8-link-$u"    C "$u" link              || { failed+=("$u:link"); continue; }
done
use_vm run
for u in "${UTILS[@]}"; do
    [ -x "$IOCS_HOME/$RES/$u/$u.new" ] || continue
    ev_run "9-check-$u" C "$u" check || failed+=("$u:check")
done
{
    if [ "$MODE" = tree ]; then
        echo "coreutils $COREUTILS_VERSION, workloads benchmarks/coreutils/<u>.dta.args, rewrite mode: pointer offset trees"
        echo "(IOCS_REWRITE_MODE=tree): SUTURE's tainted variables, a tainted pointer parameter lifted to the caller objects"
        echo "it points to; stores replace the stack write."
    else
        echo "coreutils $COREUTILS_VERSION, workloads benchmarks/coreutils/<u>.dta.args, rewrite mode: every local variable of"
        echo "the functions executed under DTA, in every object of the program (--directory mode)."
    fi
    echo
    printf '%-10s %6s %10s %10s %13s %10s %6s %8s   %s\n' utility LoC 'fns(DTA)' 'fns(rw)' compartments redirected syncs 'SUTURE' 'check: orig/iocs exit, stdout same, no-table exit'
    for u in "${UTILS[@]}"; do
        # (|| true: lib.sh runs with set -e, and a utility that stopped early has no check.txt)
        row=$(C "$u" counts 2>/dev/null | tail -1 || true); chk=$(cat "$IOCS_HOME/$RES/$u/check.txt" 2>/dev/null || true)
        printf '%s   %s\n' "${row:-$u (no counts)}" "${chk:-not checked}"
    done
    echo
    echo "LoC: lines of src/<u>.c. fns(DTA): distinct functions in the PIN trace (includes libcoreutils)."
    echo "fns(rw): of those, functions defined in the program's own objects (the rewriter's scope)."
    echo "compartments: slots the rewritten code uses (tree mode: compartments.txt, which lists the table's unused,"
    echo "placeholder and padding slots apart; directory mode: slots in table.c). redirected: accesses through a"
    echo "compartment page. syncs: stack -> page copies after calls and writes the rewriter cannot name"
    echo "(scripts/count_sites.sh)."
    echo "SUTURE: warnings in <u>.vuln."
    echo "Paper Table 1 (LoC / variables / functions): basename 191/5/1, pwd 395/12/8, wc 875/39/7,"
    echo "cp 1227/28/7, factor 2662/216/42, ls 5309/154/91."
} > "$EVID/table1.txt"
for u in "${UTILS[@]}"; do
    R=$IOCS_HOME/$RES/$u; mkdir -p "$EVID/$u"
    for f in hybrid-taint.txt hybrid-taint.dot table.c check.txt "$u.config" "$u.vuln" "$u.analysis" objects.txt \
             trees.txt lifted.txt compartments.txt; do [ -f "$R/$f" ] && cp "$R/$f" "$EVID/$u/"; done
    # (tree mode: the variables kept on the stack, with the reason, from the rewrite's log)
    [ "$MODE" = tree ] && sed 's/\x1b\[[0-9;]*m//g' "$EVID/7-rewrite-$u.log" 2>/dev/null \
        | sed -n 's/.*consistency: \([^ ]*\): \([^ ]*\) stays on the stack (\([^:]*\):.*/\1 \2 \3/p' | sort -u > "$EVID/$u/kept-on-stack.txt"
    ev_sites "$R" "$EVID/$u/rewritten-sites.txt"
    ( cd "$R" && shasum -a 256 "$u.out" "$u.new" lib/table.so table.c 2>/dev/null ) > "$EVID/$u/sha256.txt"
done
cat "$EVID/table1.txt" | tee -a "$EVID/summary.txt" >&2
ev_finalize
[ ${#failed[@]} -eq 0 ] && ev_summary "result:            PASS" || { ev_summary "result:            FAIL (${failed[*]})"; exit 1; }
