#!/bin/bash
# Rewrite every coreutils 8.31 program with every function of its own objects as the target set (a
# static superset of any DTA trace), relink it, and smoke-test it. A robustness check of the
# rewriter on a large code base; it does not replace the DTA-driven Table 1 run.
#   scripts/sweep_coreutils.sh [program...]      default: every program in the tree's bin_PROGRAMS
#   scripts/sweep_coreutils.sh --report <evidence dir> [program...]   rebuild sweep.txt from the logs
# Results go to build/sweep/result/<u>/ (IOCS_RESULT_DIR), so result/ is not touched.
# (In tree mode: build/tree-sweep/result/<u>/.)
#   build VM: migrate + all-functions (20.04 image), rewrite (iocs:dev, SWEEP_JOBS in parallel,
#             SWEEP_TIMEOUT each), link (20.04 image, one at a time: programs share objects)
#   run VM:   smoke: --version and --help against the original, with table.so; without it;
#             the Table 1 workload too for the utilities that have one (needs FSGSBASE)
# Evidence: evidence/coreutils-sweep/<UTC stamp>/: sweep.txt (one row per program), per-step logs,
# and logs/<u>.rewrite.log.xz for every program whose rewrite failed.
# SWEEP_MODE=tree: the pointer offset tree rewriter (IOCS_REWRITE_MODE=tree) instead, which needs
# SUTURE's tainted variables: after migrate, bitcode of every object (iocs-suture:llvm9: llvm-link)
# and iocs.sh sta (iocs:dev: STA entry config + SUTURE, SWEEP_JOBS in parallel, SUTURE_TIMEOUT each);
# results in build/tree-sweep/result, evidence in evidence/coreutils-tree-sweep/ (also trees.txt,
# lifted.txt, compartments.txt, kept-on-stack.txt over all programs). SUTURE's results do not depend
# on the rewriter: SWEEP_MODE=tree SWEEP_STEPS="rewrite link smoke" reruns the tree rewrite on them.
# SWEEP_STEPS (default: every step) runs only some of: migrate sta rewrite link smoke; the
# results of the steps not run are kept (a rewrite starts again from the migrated objects).
. "$(dirname "$0")/lib.sh"
CU=/iocs/build/coreutils/coreutils-$COREUTILS_VERSION; HCU=$IOCS_HOME/build/coreutils/coreutils-$COREUTILS_VERSION
MODE=${SWEEP_MODE:-directory}; SUB=sweep; [ "$MODE" = tree ] && SUB=tree-sweep
SW=/iocs/build/$SUB/result; HSW=$IOCS_HOME/build/$SUB/result; LOGS=build/$SUB/logs
STEPS=" ${SWEEP_STEPS:-migrate sta rewrite link smoke} "; step() { case $STEPS in *" $1 "*) return 0 ;; esac; return 1; }
[ -x "$HCU/src/ls" ] || die "coreutils tree not built: scripts/run_coreutils.sh builds it"
if [ "${1:-}" = --report ]; then REPORT_ONLY=${2:?evidence dir}; shift 2; fi
PROGS=("$@")
if [ ${#PROGS[@]} -eq 0 ]; then
    # bin_PROGRAMS minus "[" (test under another name)
    while read -r p; do PROGS+=("$p"); done < <(sed -n '/^bin_PROGRAMS = /,/[^\\]$/p' "$HCU/Makefile" \
        | tr ' \\' '\n\n' | sed -n 's#^src/\(.*\)$(EXEEXT)$#\1#p' | grep -vx '\[' )
fi
if [ -z "${REPORT_ONLY:-}" ]; then
if step migrate; then rm -rf "$HSW" "$IOCS_HOME/$LOGS"; fi; mkdir -p "$HSW" "$IOCS_HOME/$LOGS"
E=(env COREUTILS_HOME=$CU IOCS_RESULT_DIR=$SW)
evidence_start coreutils-$SUB
echo "programs:   ${#PROGS[@]}" >> "$EVID/env.txt"
echo "mode:       $MODE, steps:$STEPS" >> "$EVID/env.txt"
if step migrate || step sta || step rewrite || step link; then use_vm build; ev_images; fi
step migrate && ev_run 1-migrate in_image iocs-nginx-build:20.04 "${E[@]}" bash -c \
    'for u; do bash benchmarks/coreutils/coreutils.sh "$u" migrate && bash benchmarks/coreutils/coreutils.sh "$u" all-functions || echo "SWEEP $u migrate FAILED"; done' _ "${PROGS[@]}"
if [ "$MODE" = tree ] && step sta; then
    ev_run 1-bitcode in_image iocs-suture:llvm9 "${E[@]}" BITCODE_OBJECTS=1 bash -c \
        'for u; do bash benchmarks/coreutils/coreutils.sh "$u" bitcode > '"$LOGS"'/$u.bitcode.log 2>&1 && echo "SWEEP $u bitcode ok" || echo "SWEEP $u bitcode FAILED"; done' _ "${PROGS[@]}"
    ev_run 1-sta in_image iocs:dev "${E[@]}" SUTURE_TIMEOUT="${SUTURE_TIMEOUT:-1800}" bash -c '
        st() { ./iocs.sh "$1" sta > '"$LOGS"'/$1.sta.log 2>&1; echo "SWEEP $1 sta rc=$?"; }
        export -f st
        for u; do [ -s "'"$SW"'/$u/$u.bc" ] && echo "$u"; done | xargs -P '"${SWEEP_JOBS:-4}"' -I{} bash -c "st {}"' _ "${PROGS[@]}"
fi
if step rewrite; then
    RW=(); [ "$MODE" = tree ] && RW=(IOCS_REWRITE_MODE=tree)
    ev_run 2-rewrite in_image iocs:dev "${E[@]}" ${RW[@]+"${RW[@]}"} bash -c '
        rw() {
            # tree: start again from the compiler'"'"'s objects (a rerun must not rewrite rewritten code)
            if [ "${IOCS_REWRITE_MODE:-}" = tree ]; then rm -f "'"$SW"'/$1"/*.s.bak "'"$SW"'/$1"/table.c "'"$SW"'/$1"/trees.txt
                bash benchmarks/coreutils/coreutils.sh "$1" migrate > /dev/null 2>&1 || { echo "SWEEP $1 rewrite rc=restore"; return; }; fi
            timeout '"${SWEEP_TIMEOUT:-1800}"' ./iocs.sh "$1" rewrite > '"$LOGS"'/$1.rewrite.log 2>&1; rc=$?; echo "SWEEP $1 rewrite rc=$rc"; }
        export -f rw
        for u; do [ -s "'"$SW"'/$u/$u.analysis" ] && echo "$u"; done | xargs -P '"${SWEEP_JOBS:-4}"' -I{} bash -c "rw {}"' _ "${PROGS[@]}"
fi
step link && ev_run 3-link in_image iocs-nginx-build:20.04 "${E[@]}" bash -c \
    'for u; do [ -f "'"$SW"'/$u/table.c" ] || continue; bash benchmarks/coreutils/coreutils.sh "$u" link > /dev/null 2>&1 && echo "SWEEP $u link ok" || echo "SWEEP $u link FAILED"; done' _ "${PROGS[@]}"
if step smoke; then
use_vm run; ev_images
ev_run 4-smoke in_image iocs-nginx-build:20.04 "${E[@]}" bash -c \
    'for u; do [ -x "'"$SW"'/$u/$u.new" ] && echo "SMOKE $(bash benchmarks/coreutils/coreutils.sh "$u" smoke 2>&1 | tail -1)"; done' _ "${PROGS[@]}"
fi
fi
# One row per program (scripts/sweep_coreutils.sh --report <evidence dir> rebuilds it from the logs).
# A step's log: this run's, else the newest earlier run's (SWEEP_STEPS runs only some steps).
steplog() {
    local f; for f in "$1/$2.log" $(ls -1dr "$(dirname "$1")"/*/ 2>/dev/null | sed "s#/\$#/$2.log#"); do
        [ -f "$f" ] && { cat "$f"; return; }; [ -f "$f.xz" ] && { xzcat "$f.xz"; return; }
    done; true
}
# "<fun> <slot> <reason>" of every tainted/lifted variable the tree rewrite kept on the stack
kept_on_stack() { sed 's/\x1b\[[0-9;]*m//g' "$1" 2>/dev/null | sed -n 's/.*consistency: \([^ ]*\): \([^ ]*\) stays on the stack (\([^:]*\):.*/\1 \2 \3/p' | sort -u; }
report() {
    local EVID=$1 u R L nt rc rw um comp redir syncs lk sm st warn trees rec frm
    local RWL LKL SML STL; RWL=$(steplog "$EVID" 2-rewrite); LKL=$(steplog "$EVID" 3-link); SML=$(steplog "$EVID" 4-smoke)
    if [ "$MODE" = tree ]; then STL=$(steplog "$EVID" 1-sta)
        printf '%-10s %-7s %5s %5s %-26s %5s %5s %5s %5s %6s %5s %-6s %s
' program sta warn. trees rewrite unmod comp. redir syncs rec. other link smoke
    else printf '%-12s %-9s %-34s %6s %6s %6s %6s %-6s %s
' program targets rewrite unmod. comp. redir. syncs link smoke; fi
    for u in "${PROGS[@]}"; do
        R=$HSW/$u; L=$IOCS_HOME/$LOGS/$u.rewrite.log
        # (each lookup may find nothing; lib.sh runs with set -e)
        nt=$(tr ',' '\n' < "$R/$u.analysis" 2>/dev/null | grep -c . || true)
        rc=$(echo "$RWL" | sed -n "s/^SWEEP $u rewrite rc=//p" | tail -1 || true)
        if [ -z "$rc" ]; then rw="not run"; elif [ "$rc" = 0 ]; then rw=ok; elif [ "$rc" = 124 ]; then rw=timeout
        else rw="rc=$rc $(grep -E '^[A-Za-z]+(Error|Exception)' "$L" 2>/dev/null | tail -1 | cut -c1-20 || true)"; fi
        um=$(grep -c 'Unsupported instruction shape' "$L" 2>/dev/null || true)
        if [ "$MODE" = tree ]; then comp=$(sed -n 's/^compartments: \([0-9]*\).*/\1/p' "$R/compartments.txt" 2>/dev/null || true)
        else comp=$(grep -oE 'malloc\(sizeof\(void\*\) *\* *[0-9]+\)' "$R/table.c" 2>/dev/null | grep -oE '[0-9]+\)$' | tr -d ')' || true); fi
        read -r redir syncs <<< "$(bash "$IOCS_HOME/scripts/count_sites.sh" "$R"/*.s)"
        lk=$(echo "$LKL" | sed -n "s/^SWEEP $u link //p" | tail -1 || true)
        sm=$(echo "$SML" | sed -n "s/^SMOKE $u //p" | tail -1 || true)
        if [ "$MODE" = tree ]; then
            st=$(echo "$STL" | sed -n "s/^SWEEP $u sta rc=//p" | tail -1 || true)
            warn=$(grep -c '^file:' "$R/$u.vuln" 2>/dev/null || true)
            trees=$(grep -c '^Root Function:' "$R/trees.txt" 2>/dev/null || true)
            # variables kept on the stack (tree_stack_only, rewriter.py): recursive function / any other reason
            # (each rewrite pass logs them again: one per function and slot)
            kept=$(kept_on_stack "$L")
            rec=$(echo "$kept" | grep -c ' recursive$' || true); frm=$(echo "$kept" | grep -c . || true); frm=$((frm - rec))
            printf '%-10s %-7s %5s %5s %-26s %5s %5s %5s %5s %6s %5s %-6s %s\n' "$u" "${st:--}" "${warn:-0}" "${trees:-0}" "$rw" "${um:-0}" "${comp:--}" "$redir" "$syncs" "${rec:-0}" "${frm:-0}" "${lk:--}" "${sm:--}"
        else
            printf '%-12s %-9s %-34s %6s %6s %6s %6s %-6s %s\n' "$u" "${nt:-0}" "$rw" "${um:-0}" "${comp:--}" "$redir" "$syncs" "${lk:--}" "${sm:--}"
        fi
    done
}
if [ "${REPORT_ONLY:-}" ]; then report "$REPORT_ONLY"; exit 0; fi
report "$EVID" > "$EVID/sweep.txt"
if [ "$MODE" = tree ]; then
    for u in "${PROGS[@]}"; do kept_on_stack "$IOCS_HOME/$LOGS/$u.rewrite.log" | sed "s/^/$u /"; done > "$EVID/kept-on-stack.txt"
    awk '{print $4}' "$EVID/kept-on-stack.txt" | sort | uniq -c | sort -rn > "$EVID/kept-on-stack-reasons.txt"
    for u in "${PROGS[@]}"; do [ -f "$HSW/$u/trees.txt" ] && { echo "== $u"; sed -n '/^# Function summaries/q;p' "$HSW/$u/trees.txt"; } || true; done > "$EVID/trees.txt"
    # lifts and kept slots (lifted.txt), and the compartments each program's rewritten code uses
    for u in "${PROGS[@]}"; do [ -f "$HSW/$u/lifted.txt" ] && grep -v '^#' "$HSW/$u/lifted.txt" | sed "s/^/$u /" || true; done > "$EVID/lifted.txt"
    for u in "${PROGS[@]}"; do [ -f "$HSW/$u/compartments.txt" ] && { echo "== $u"; cat "$HSW/$u/compartments.txt"; } || true; done > "$EVID/compartments.txt"
fi
mkdir -p "$EVID/logs"
for u in "${PROGS[@]}"; do
    grep -qE "^$u .* ok " "$EVID/sweep.txt" || { [ -f "$IOCS_HOME/$LOGS/$u.rewrite.log" ] && xz -9 -c "$IOCS_HOME/$LOGS/$u.rewrite.log" > "$EVID/logs/$u.rewrite.log.xz"; } || true
done
total=${#PROGS[@]}
col=3; [ "$MODE" = tree ] && col=5
ok_rw=$(awk -v c=$col 'NR>1 && $c=="ok"' "$EVID/sweep.txt" | wc -l | tr -d ' ')
ok_sm=$(grep -c ' PASS' "$EVID/sweep.txt" || true)
ev_summary "programs:          $total"
ev_summary "rewrite ok:        $ok_rw"
ev_summary "smoke PASS:        $ok_sm"
ev_finalize
say "done: ${EVID#$IOCS_HOME/}/sweep.txt"
