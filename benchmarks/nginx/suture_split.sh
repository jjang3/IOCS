#!/bin/bash
# SUTURE on Nginx one entry function at a time (iocs:dev): suture_split.sh <result dir>
#   <result dir> holds nginx.bc and nginx.config (the DTA entry config, nginx.sh sta / sta/main.py);
#   writes nginx.taint, nginx.vuln (as iocs.sh sta does), suture-entries.txt (one line per entry:
#   status, seconds, warnings) and, under suture/, each entry's status and the warning part of its
#   log (xz).
# Why: SUTURE analyses an entry's calls context-sensitively, so with every DTA function of Nginx
# as an entry (79) one run did not get past its first entry (ngx_conf_parse, which reaches the
# configuration handlers) in an hour, and the whole run would take days. Run apart, every entry
# gets SUTURE_ENTRY_TIMEOUT seconds (SUTURE_JOBS at once); the warnings of the entries that finish
# are merged, and an entry that does not finish is listed as a timeout. What is lost: taint
# that needs two entries in sequence (SUTURE's higher-order flows through globals).
# An entry with a status in suture/ is not run again (SUTURE_RESUME=0 runs every entry).
# SUTURE's debug log grows by GBs per entry; only what ext_warns.py reads is kept (the lines
# between its @@@@@@ markers) and the completion marker.
set -u
RES=${1:?result dir}; T=${SUTURE_ENTRY_TIMEOUT:-1200}; J=${SUTURE_JOBS:-6}
SUTURE_HOME=${SUTURE_HOME:-/opt/suture}
[ -s "$RES/nginx.bc" ] && [ -s "$RES/nginx.config" ] || { echo "suture_split.sh: need $RES/nginx.bc and nginx.config" >&2; exit 1; }
W=$SUTURE_HOME/benchmark/split; rm -rf "$W"; mkdir -p "$W" "$RES/suture"
[ "${SUTURE_RESUME:-1}" = 1 ] || rm -f "$RES"/suture/*
cp "$RES/nginx.bc" "$W/nginx.bc"
n=0; while read -r line; do [ -n "$line" ] || continue; n=$((n+1)); echo "$line" > "$W/e$n.config"; done < "$RES/nginx.config"
one() {
    local c=$1 W=$2 T=$3 RES=$4; local name; name=$(cut -d' ' -f1 "$W/$c.config")
    local start; start=$(date +%s)
    ( cd "$SUTURE_HOME" && . ./env.sh && timeout "$T" opt -load llvm_analysis/MainAnalysisPasses/build_dir/SoundyAliasAnalysis/libSoundyAliasAnalysis.so \
        -dr_checker -entryConfig="$W/$c.config" -outputFile="$W/$c.warn.json" -instrWarnings="$W/$c.iwarn.json" \
        "$W/nginx.bc" -o /dev/null 2>&1 \
        | awk '/^@@@@@@/ {w = !w; print; next} w {print; next} /Bug Detection Phase finished/ {print}' > "$W/$c.log"
      exit "${PIPESTATUS[0]}" )
    local rc=$? secs=$(( $(date +%s) - start )) st
    if grep -q 'Bug Detection Phase finished' "$W/$c.log"; then
        st=done; xz -1 -c "$W/$c.log" > "$RES/suture/$c-$name.log.xz"
    elif [ $rc = 124 ]; then st=timeout; else st="rc=$rc"; fi
    rm -f "$W/$c.log"
    echo "$c $name $st ${secs}s" > "$RES/suture/$c.status"
}
export -f one; export SUTURE_HOME
for f in "$W"/e*.config; do c=$(basename "$f" .config); grep -qE ' (done|timeout) ' "$RES/suture/$c.status" 2>/dev/null || echo "$c"; done \
    | sort -V | xargs -r -P "$J" -I{} bash -c 'one {} "$0" "$1" "$2"' "$W" "$T" "$RES"
# Per entry the warnings ext_warns.py reports, merged; then .vuln as iocs.sh sta writes it
: > "$RES/nginx.taint"; : > "$RES/suture-entries.txt"
for i in $(seq "$n"); do
    s=$(cat "$RES/suture/e$i.status" 2>/dev/null || echo "e$i ? missing"); warns=0
    log=$(ls "$RES"/suture/e$i-*.log.xz 2>/dev/null | head -1)
    if [ -n "$log" ] && echo "$s" | grep -q ' done '; then
        xzcat "$log" > "$W/e$i.log"
        ( cd "$SUTURE_HOME" && python ext_warns.py "$W/e$i.log" IntegerOverflowDetector TaintedLoopBoundDetector \
            TaintedPointerDereferenceChecker ImproperTaintedDataUseDetector 2>/dev/null ) > "$W/e$i.all"
        warns=$(grep -c ' says: ' "$W/e$i.all" || true)
        cat "$W/e$i.all" >> "$RES/nginx.taint"; echo >> "$RES/nginx.taint"; rm -f "$W/e$i.log"
    fi
    echo "$s $warns" >> "$RES/suture-entries.txt"
done
grep -oP "([^ ]+) says: ([^@]+)@([0-9]+) \(([^:]+) :(.+)" "$RES/nginx.taint" |
gawk -F' : ' '{
    match($0, /([^ ]+) says: ([^@]+)@([0-9]+) \(([^:]+) :(.+)/, m);
    instruction = m[5]; gsub(/\)$/, "", instruction);
    print "file: " m[2] " - line_num: " m[3] " - fun_name: " m[4] "\n\t\t\t- vuln_type: " m[1] "\n\t\t\t- instruction: " instruction "\n";
}' > "$RES/nginx.vuln"
echo "suture_split.sh: $(grep -c ' done ' "$RES/suture-entries.txt") of $n entries finished within ${T}s ($(grep -c ' timeout ' "$RES/suture-entries.txt") timeouts); $(grep -c '^file:' "$RES/nginx.vuln") warnings"
