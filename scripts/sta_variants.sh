#!/bin/bash
# SUTURE options experiment: does the set of functions SUTURE warns in depend on how the
# bitcode is built? Needs a previous scripts/run.sh <target> (for result/<target>/<target>.config).
#   scripts/sta_variants.sh [target]          (default: tiny)
# Evidence: evidence/sta-variants-<target>/<UTC stamp>/ (variants.log, one .taint per recipe).
. "$(dirname "$0")/lib.sh"
t=${1:-tiny}
[ -f "$IOCS_HOME/result/$t/$t.config" ] || die "no result/$t/$t.config: run scripts/run.sh $t first"
evidence_start "sta-variants-$t"
use_vm build; ev_images
ev_run variants in_image iocs:dev bash src/sta/suture_variants.sh "/iocs/result/$t" "$t" "/iocs/${EVID#$IOCS_HOME/}"
grep -E '^(iocs|o1|o0mem2reg):' "$EVID/variants.log" | tee "$EVID/summary.txt" >&2
ev_finalize
