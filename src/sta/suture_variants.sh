#!/bin/bash
# Run SUTURE on one program with several bitcode recipes and the same entry configuration, and
# report which functions it warns in. Runs inside iocs:dev (scripts/sta_variants.sh wraps it).
#   src/sta/suture_variants.sh <result dir> <target> <out dir>
# Recipes:
#   iocs        clang -emit-llvm -g -c                                  (what iocs.sh uses)
#   o1          clang -emit-llvm -g -c -O1                              (SUTURE benchmark/gen.sh)
#   o0mem2reg   clang -emit-llvm -g -c -O0 -Xclang -disable-O0-optnone, then opt -mem2reg
#                                                                       (SUTURE benchmark/gen-O0-mem2reg.sh)
set -u
R=${1:?result dir}; t=${2:?target}; OUT=${3:?out dir}; mkdir -p "$OUT"
S=$SUTURE_HOME; C=$SUTURE_CLANG; src=$(cd "$(dirname "$0")/../.." && pwd)/benchmarks/$t.c
[ -f "$R/$t.config" ] || { echo "no $R/$t.config: run ./iocs.sh $t sta first"; exit 2; }
build() { case $1 in
  iocs)      "$C" -emit-llvm -g -c -o "$2" "$src" ;;
  o1)        "$C" -emit-llvm -g -c -O1 -o "$2" "$src" ;;
  o0mem2reg) "$C" -emit-llvm -Xclang -disable-O0-optnone -g -c -O0 -o "$2.tmp.bc" "$src" && opt -mem2reg "$2.tmp.bc" -o "$2" ;;
esac; }
for v in iocs o1 o0mem2reg; do
  n=${t}_$v; bc=$S/benchmark/$n.bc; cfg=$S/benchmark/$n.config
  build $v "$bc" 2>/dev/null || { echo "$v: bitcode build failed"; continue; }
  cp "$R/$t.config" "$cfg"
  ( cd "$S" && . ./env.sh && rm -f "benchmark/$n.config.log" && ./run_nohup.sh "benchmark/$n.bc" "benchmark/$n.config"
    timeout "${SUTURE_TIMEOUT:-3600}" bash -c "until grep -q 'Bug Detection Phase finished' benchmark/$n.config.log 2>/dev/null; do sleep 2; done"
    ./ext_warns.sh "benchmark/$n.config.log" > /dev/null 2>&1 )
  d=$(ls -1dt "$S"/benchmark/warns-$n.config-* 2>/dev/null | head -1)
  [ -n "$d" ] || { echo "$v: SUTURE produced no report"; continue; }
  cp "$d/all" "$OUT/$n.taint"
  fns=$(grep -oE "says: [^@]+@[0-9]+ \(([A-Za-z_][A-Za-z0-9_]*)" "$OUT/$n.taint" | grep -oE "\([A-Za-z_0-9]+" | tr -d '(' | sort | uniq -c | awk '{printf "%s(%s) ", $2, $1}')
  echo "$v: warnings in: ${fns:-none}"
done
