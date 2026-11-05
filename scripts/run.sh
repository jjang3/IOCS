#!/bin/bash
# Run the IOCS pipeline end to end on benchmarks/<target>.c and record the evidence.
#   scripts/run.sh [target]            (default: tiny)
# Stages and where they run (macOS: VMs are switched automatically; Linux: one daemon):
#   build VM: tools build             (PIN tool + compile benchmarks/<target>.c)
#   run VM:   dta                     (PIN needs ptrace; drives the program via benchmarks/<target>.dta.sh)
#   build VM: sta rewrite link        (SUTURE, Binary Ninja analysis, rewriting, table.so)
#   run VM:   benchmarks/<target>.check.sh if present (tiny: tests/serve_tiny.sh; needs FSGSBASE)
# IOCS_REWRITE_MODE=directory (default) | binary | tree selects the rewriter (see iocs.sh); a
# non-default mode records under evidence/<target>-<mode>/.
# Evidence: evidence/<target>/<UTC stamp>/ : env.txt, one .log per step, summary.txt, sha256.txt,
# hybrid-taint.{txt,dot} (DTA vs SUTURE per function), the SUTURE config/warnings/log, table.c.
# A previous result/<target>/ is moved to build/old/ first (nothing is deleted).
. "$(dirname "$0")/lib.sh"
t=${1:-tiny}
[ -f "$IOCS_HOME/benchmarks/$t.c" ] || die "no benchmarks/$t.c"
mode=${IOCS_REWRITE_MODE:-directory}
case $mode in directory|binary|tree) ;; *) die "IOCS_REWRITE_MODE must be directory, binary or tree" ;; esac
name=$t; [ "$mode" = directory ] || name=$t-$mode
fix_owner
if [ -d "$IOCS_HOME/result/$t" ]; then
    mkdir -p "$IOCS_HOME/build/old"; mv "$IOCS_HOME/result/$t" "$IOCS_HOME/build/old/result-$t-$(date -u +%Y%m%dT%H%M%SZ)"
fi
evidence_start "$name"
use_vm build; ev_images
ev_run 1-tools-build  in_image iocs:dev bash -c "./iocs.sh $t tools build && cp result/$t/$t.s result/$t/$t.s.compiler"
use_vm run; ev_images
ev_run 2-dta          in_image iocs:dev ./iocs.sh "$t" dta
use_vm build
ev_run 3-sta          in_image iocs:dev ./iocs.sh "$t" sta
ev_run 4-rewrite      in_image iocs:dev env IOCS_REWRITE_MODE=$mode ./iocs.sh "$t" rewrite
ev_run 5-link         in_image iocs:dev ./iocs.sh "$t" link
R=$IOCS_HOME/result/$t
ev_summary "target:            $t"
ev_summary "rewrite mode:      $mode"
ev_summary "dta functions:     $(tr ',' '\n' < "$R/$t.analysis" | grep -c . ) calls, $(tr ',' '\n' < "$R/$t.analysis" | grep . | sort -u | wc -l | tr -d ' ') distinct"
ev_summary "sta entry config:  $(wc -l < "$R/$t.config" | tr -d ' ') lines; vuln warnings: $(grep -c '^file:' "$R/$t.vuln" || true)"
for f in hybrid-taint.txt hybrid-taint.dot "$t.config" "$t.vuln" "$t.suture.log"; do [ -f "$R/$f" ] && cp "$R/$f" "$EVID/"; done
ev_summary "found by DTA and SUTURE: $(sed -n 's/^both: //p' "$R/hybrid-taint.txt")"
ev_summary "found by DTA only:       $(sed -n 's/^DTA only: //p' "$R/hybrid-taint.txt")"
ev_summary "found by SUTURE only:    $(sed -n 's/^SUTURE only: //p' "$R/hybrid-taint.txt")"
if [ "$mode" = tree ]; then   # (slots the rewritten code uses; compartments.txt lists the table's others)
    ev_summary "compartments:      $(sed -n 's/^compartments: //p' "$R/compartments.txt")"
    ev_summary "table:             $(sed -n 2p "$R/compartments.txt")"
    for f in trees.txt lifted.txt compartments.txt; do cp "$R/$f" "$EVID/"; done
else
ev_summary "compartments:      $(grep -oE 'malloc\(sizeof\(void\*\) *\* *[0-9]+\)' "$R/table.c" | grep -oE '[0-9]+\)$' | tr -d ')')"
fi
read -r redir syncs <<< "$(bash "$IOCS_HOME/scripts/count_sites.sh" "$R/$t.s")"
ev_summary "redirected sites:  $redir (accesses through a compartment page)"
ev_summary "sync copies:       $syncs (lea_store_gs, stack -> page; scripts/count_sites.sh)"
ev_summary "unmodelled insts:  $(grep -c 'Unsupported instruction shape' "$EVID/4-rewrite.log" || true) (skipped, see 4-rewrite.log)"
cp "$R/table.c" "$EVID/table.c"; diff "$R/$t.s.compiler" "$R/$t.s" > "$EVID/rewrite.diff" || true
ev_sites "$R" "$EVID/rewritten-sites.txt"
( cd "$R" && sha256sum "$t.out" "$t.s.compiler" "$t.s" table.c lib/table.so "$t.new" 2>/dev/null || shasum -a 256 "$t.out" "$t.s.compiler" "$t.s" table.c lib/table.so "$t.new" ) > "$EVID/sha256.txt"
# Runtime check: benchmarks/<target>.check.sh, run in iocs:dev on the FSGSBASE daemon with
# TARGET_DIR pointing at result/<target> (tiny's runs tests/serve_tiny.sh).
if [ -f "$IOCS_HOME/benchmarks/$t.check.sh" ]; then
    use_vm run
    if ev_run 6-check in_image iocs:dev env TARGET_DIR="/iocs/result/$t" bash "benchmarks/$t.check.sh"; then
        ev_summary "runtime check:     $(grep -oE '[A-Za-z_]+: PASS' "$EVID/6-check.log" | tail -1)"
    else ev_summary "runtime check:     FAIL (see 6-check.log)"; ev_finalize; exit 1; fi
else
    ev_summary "runtime check:     none (no benchmarks/$t.check.sh)"
fi
ev_finalize
say "done: ${EVID#$IOCS_HOME/}/summary.txt"
