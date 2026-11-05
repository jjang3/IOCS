#!/bin/bash
# Copy the binaries a recorded run tested into artifacts/<run>/, checking each against the
# SHA-256 that run recorded, so every artifact traces back to its evidence.
#   scripts/export_artifacts.sh tiny  [evidence/tiny/<stamp>]    (default: newest)
#   scripts/export_artifacts.sh nginx [evidence/nginx/<stamp>]
. "$(dirname "$0")/lib.sh"
run=${1:?tiny or nginx}; ev=${2:-$(ls -1d "$IOCS_HOME"/evidence/$run/*/ 2>/dev/null | tail -1)}; ev=${ev%/}
[ -f "$ev/sha256.txt" ] || die "no recorded run under evidence/$run"
A=$IOCS_HOME/artifacts/$run; mkdir -p "$A/lib"
put() {  # <source relative to its sha256.txt base> <destination name>
    local src=$1 dst=$2 want got
    want=$(awk -v f="$3" '$2==f {print $1}' "$ev/sha256.txt")
    [ -n "$want" ] || die "$3 not recorded in $ev/sha256.txt"
    got=$( (shasum -a 256 "$src" 2>/dev/null || sha256sum "$src") | awk '{print $1}')
    [ "$got" = "$want" ] || die "$src does not match the recorded hash (was it rebuilt since $ev?)"
    cp "$src" "$A/$dst"; echo "$want  $dst" >> "$A/SHA256SUMS"
}
: > "$A/SHA256SUMS"
case $run in
  tiny)  R=$IOCS_HOME/result/tiny
         put "$R/tiny.out" tiny.orig tiny.out; put "$R/tiny.new" tiny.new tiny.new
         put "$R/lib/table.so" lib/table.so lib/table.so; put "$R/table.c" table.c table.c ;;
  nginx) N=build/nginx/nginx-$NGINX_VERSION
         put "$IOCS_HOME/build/nginx/nginx.orig" nginx.orig build/nginx/nginx.orig
         put "$IOCS_HOME/$N/objs/nginx" nginx "$N/objs/nginx"
         put "$IOCS_HOME/$N/objs/src/lib/table.so" lib/table.so "$N/objs/src/lib/table.so"
         put "$IOCS_HOME/$N/objs/src/table.c" table.c "$N/objs/src/table.c" ;;
  *) die "unknown run $run" ;;
esac
echo "${ev#$IOCS_HOME/}" > "$A/EVIDENCE"
say "artifacts/$run <- ${ev#$IOCS_HOME/}"
