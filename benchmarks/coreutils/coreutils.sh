#!/bin/bash
# Per-utility steps for the coreutils evaluation (paper Table 1). scripts/run_coreutils.sh runs
# them in order and in the right container; each can also be run by hand:
#
#   coreutils.sh <u> migrate   result/<u>/: the linked program as <u>.out, and for every object
#                              of the program its .s, .o and .intel (20.04 image, needs the tree)
#   coreutils.sh <u> bitcode   result/<u>/<u>.bc and .ll from src/<u>.c with the configured
#                              tree's include paths (iocs:dev: SUTURE's clang 9); for a program
#                              without its own src/<u>.c, or with BITCODE_OBJECTS=1, every object's
#                              source with its make flags, llvm-linked (iocs-suture:llvm9)
#   then: IOCS_TARGET_DIR=benchmarks/coreutils ./iocs.sh <u> dta sta rewrite   (iocs.sh)
#   coreutils.sh <u> link      relink the rewritten objects with the tree's own make, copy the
#                              program to result/<u>/<u>.new, restore the tree's own objects and
#                              program, build lib/table.so (20.04)
#   coreutils.sh <u> check     run original and rewritten on the workload (<u>.dta.args) and
#                              compare; the rewritten one must not work without table.so (FSGSBASE)
#   coreutils.sh <u> counts    one line: LoC, functions, compartments (tree mode: the slots the
#                              rewritten code uses, compartments.txt), redirected accesses, sync
#                              copies (scripts/count_sites.sh), SUTURE warnings
#   coreutils.sh <u> all-functions   <u>.analysis = every function defined in the program's own
#                              objects (a static superset of any DTA trace; scripts/sweep_coreutils.sh)
#   coreutils.sh <u> smoke     original vs rewritten on --version and --help (and the workload if
#                              <u>.dta.args exists); one line PASS/FAIL (FSGSBASE)
# IOCS_RESULT_DIR (default result/) is where result/<u>/ lives.
set -u
IOCS_HOME=${IOCS_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}
. "$IOCS_HOME/third_party/versions.env"
[ -f "$IOCS_HOME/config.env" ] && . "$IOCS_HOME/config.env"
COREUTILS_HOME=${COREUTILS_HOME:-$IOCS_HOME/build/coreutils/coreutils-$COREUTILS_VERSION}
u=${1:?utility}; step=${2:?step}
R=${IOCS_RESULT_DIR:-$IOCS_HOME/result}/$u; here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
die() { echo "coreutils.sh: $*" >&2; exit 1; }
[ -d "$COREUTILS_HOME/src" ] || die "coreutils tree not built: $COREUTILS_HOME (benchmarks/coreutils/build_coreutils.sh)"

# The objects a program is linked from, e.g. ls -> src/ls.o src/ls-ls.o (automake's <prog>_OBJECTS).
objects() { make -s -C "$COREUTILS_HOME" -f Makefile -f <(printf 'iocs-print-%%:\n\t@echo $($*)\n') "iocs-print-src_${u}_OBJECTS"; }

case $step in
migrate)
    mkdir -p "$R"
    cp "$COREUTILS_HOME/src/$u" "$R/$u.out"
    : > "$R/objects.txt"
    for o in $(objects); do
        b=${o%.o}; n=$(basename "$b")
        for ext in s o intel; do
            [ -f "$COREUTILS_HOME/$b.$ext" ] || die "missing $COREUTILS_HOME/$b.$ext (build with INTEL=1)"
            cp "$COREUTILS_HOME/$b.$ext" "$R/$n.$ext"
        done
        cp "$COREUTILS_HOME/$b.s.orig" "$R/$n.s.compiler" 2>/dev/null || cp "$R/$n.s" "$R/$n.s.compiler"
        echo "$o" >> "$R/objects.txt"
    done
    # (LoC of src/<u>.c; a program built from another program's source, base64 from basenc.c, has none)
    if [ -f "$COREUTILS_HOME/src/$u.c" ]; then wc -l < "$COREUTILS_HOME/src/$u.c" | tr -d ' ' > "$R/loc.txt"; else echo "?" > "$R/loc.txt"; fi
    echo "$u: $(wc -l < "$R/objects.txt" | tr -d ' ') objects, $(cat "$R/loc.txt") lines in src/$u.c" ;;
bitcode)
    C=${SUTURE_CLANG:-${LLVM_ROOT:-/opt/suture_deps/llvm/build}/bin/clang}
    [ -x "$C" ] || die "SUTURE clang not found: $C"
    if [ -f "$COREUTILS_HOME/src/$u.c" ] && [ -z "${BITCODE_OBJECTS:-}" ]; then
        ( cd "$COREUTILS_HOME" && "$C" -emit-llvm -g -c -I. -Ilib -Isrc -o "$R/$u.bc" "src/$u.c" \
            && "$(dirname "$C")/llvm-dis" "$R/$u.bc" -o "$R/$u.ll" ) || die "bitcode for $u failed"
    else
        # Every object of the program (base64 is src_base64-basenc.o, cp has six): each from its own
        # source (the .s names it) with the -I/-D/-include flags its make rule uses (per-program
        # CPPFLAGS such as -DBASE_TYPE=64), linked into one module (llvm-link: iocs-suture:llvm9).
        [ -s "$R/objects.txt" ] || die "no $R/objects.txt: run coreutils.sh $u migrate first"
        rm -rf "$R/bc"; mkdir -p "$R/bc"; bcs=()
        while read -r o; do
            n=$(basename "${o%.o}")
            f=$(sed -n 's/^[[:space:]]*\.file[[:space:]]*"\([^"]*\)".*/\1/p' "$R/$n.s.compiler" | head -1)
            src=$(dirname "$o")/$f; [ -f "$COREUTILS_HOME/$src" ] || die "no source $src for $o"
            cmd=$(make -s -n -C "$COREUTILS_HOME" -W "$src" "$o" 2>/dev/null | sed -e ':a' -e '/\\$/N; s/\\\n//; ta' | grep -F -- "-o $o " | head -1)
            [ -n "$cmd" ] || die "no compile rule for $o"
            # shellcheck disable=SC2086
            flags=$(set -f; keep=; for t in ${cmd#*;}; do
                if [ "$keep" = 1 ]; then printf ' %s' "$t"; keep=; continue; fi
                # ("(pattern)": macOS bash 3.2 cannot parse a bare "pattern)" inside $(...))
                case $t in (-include) printf ' %s' "$t"; keep=1 ;; (-I*|-D*|-U*) printf ' %s' "$t" ;; (-MT) break ;; esac
            done)
            # shellcheck disable=SC2086
            ( cd "$COREUTILS_HOME" && "$C" -emit-llvm -g -c $flags -o "$R/bc/$n.bc" "$src" ) || die "bitcode of $src failed"
            echo "$o $src$flags" >> "$R/bc/sources.txt"; bcs+=("$R/bc/$n.bc")
        done < "$R/objects.txt"
        if [ ${#bcs[@]} -eq 1 ]; then cp "${bcs[0]}" "$R/$u.bc"
        else L=${LLVM_LINK:-$(dirname "$C")/llvm-link}
             [ -x "$L" ] || die "$u has ${#bcs[@]} objects and there is no llvm-link at $L (iocs-suture:llvm9 has it)"
             "$L" "${bcs[@]}" -o "$R/$u.bc" || die "llvm-link for $u failed"; fi
        "$(dirname "$C")/llvm-dis" "$R/$u.bc" -o "$R/$u.ll" || die "llvm-dis for $u failed"
    fi
    echo "$u: $(wc -c < "$R/$u.bc" | tr -d ' ') bytes of bitcode" ;;
link)
    [ -f "$R/table.c" ] || die "no $R/table.c: run ./iocs.sh $u rewrite first"
    # Relink with the tree's own make, then put the tree back: its objects and program must stay
    # the compiler's, since migrate copies them (the originals are moved aside and moved back).
    T=$COREUTILS_HOME
    restore() { while read -r o; do [ -f "$T/$o.iocs-orig" ] && mv -f "$T/$o.iocs-orig" "$T/$o"; done < "$R/objects.txt"
                [ -f "$T/src/$u.iocs-orig" ] && mv -f "$T/src/$u.iocs-orig" "$T/src/$u"; true; }
    restore   # (a previous link that was interrupted)
    mv "$T/src/$u" "$T/src/$u.iocs-orig"
    while read -r o; do n=$(basename "${o%.o}"); mv "$T/$o" "$T/$o.iocs-orig"; cp "$R/$n.o" "$T/$o"; done < "$R/objects.txt"
    rc=0; ( cd "$T" && make -s "src/$u" ) > "$R/relink.log" 2>&1 || rc=$?
    [ $rc -eq 0 ] && cp "$T/src/$u" "$R/$u.new"
    rm -f "$T/src/$u"; restore
    [ $rc -eq 0 ] || { tail -5 "$R/relink.log" >&2; die "relink of $u failed"; }
    cp "$IOCS_HOME/benchmarks/libMakefile" "$R/Makefile"
    ( cd "$R" && make -s lib ) > "$R/lib.log" 2>&1 || { tail -5 "$R/lib.log" >&2; die "table.so for $u failed"; }
    echo "$u: relinked ($(grep -c ' -c ' "$R/relink.log") C files recompiled), lib/table.so built" ;;
check)
    [ -x "$R/$u.new" ] || die "no $R/$u.new: run coreutils.sh $u link first"
    run_one() {  # <label> <binary> [preload]
        local label=$1 bin=$2 pre=${3:-}; local work; work=$(mktemp -d)
        local DTA_ARGS=() DTA_STDIN=/dev/null; unset -f dta_verify 2>/dev/null
        # shellcheck disable=SC1090
        . "$here/$u.dta.args"
        # CHECK_TIMEOUT bounds each run (a rewritten program that loops counts as exit 124).
        ( cd "$work" && if [ -n "$pre" ]; then LD_PRELOAD=$pre timeout "${CHECK_TIMEOUT:-60}" "$bin" ${DTA_ARGS[@]+"${DTA_ARGS[@]}"}; else timeout "${CHECK_TIMEOUT:-60}" "$bin" ${DTA_ARGS[@]+"${DTA_ARGS[@]}"}; fi \
            < "$DTA_STDIN" > "$work/stdout.raw" 2> "$work/stderr" ); local rc=$?
        # Each run has its own directory; name it WORK so that output naming it (pwd, ls -l) compares.
        sed "s#$work#WORK#g" "$work/stdout.raw" > "$work/stdout"
        local v=n/a; if declare -f dta_verify >/dev/null; then dta_verify && v=ok || v=FAIL; fi
        echo "$rc $v $work"
    }
    read -r rc0 v0 w0 <<< "$(run_one original "$R/$u.out")"
    read -r rc1 v1 w1 <<< "$(run_one iocs "$R/$u.new" "$R/lib/table.so")"
    read -r rc2 v2 w2 <<< "$(run_one no-table "$R/$u.new")"
    same=yes; cmp -s "$w0/stdout" "$w1/stdout" || same=no
    echo "[$u] original: exit $rc0 verify $v0 | iocs+table.so: exit $rc1 verify $v1 stdout-identical $same | without table.so: exit $rc2"
    echo "$rc0 $v0 $rc1 $v1 $same $rc2" > "$R/check.txt"
    [ "$rc0" = "$rc1" ] && [ "$same" = yes ] && [ "$v1" != FAIL ] || die "$u: rewritten program differs from the original" ;;
counts)
    loc=$(cat "$R/loc.txt" 2>/dev/null)
    fx=$(tr ',' '\n' < "$R/$u.analysis" 2>/dev/null | grep . | sort -u | wc -l | tr -d ' ')
    defined=$(grep -hoE '^\s*\.type\s+[A-Za-z_][A-Za-z0-9_.]*,\s*@function' "$R"/*.s.compiler 2>/dev/null | sed -E 's/.*\.type\s+//; s/,.*//' | sort -u)
    fr=$(comm -12 <(echo "$defined") <(tr ',' '\n' < "$R/$u.analysis" 2>/dev/null | grep . | sort -u) | wc -l | tr -d ' ')
    # tree mode: the slots the rewritten code uses (compartments.txt); else the slots in table.c
    if [ -f "$R/compartments.txt" ]; then comp=$(sed -n 's/^compartments: \([0-9]*\).*/\1/p' "$R/compartments.txt")
    else comp=$(grep -oE 'malloc\(sizeof\(void\*\) *\* *[0-9]+\)' "$R/table.c" 2>/dev/null | grep -oE '[0-9]+\)$' | tr -d ')'); fi
    read -r redir syncs <<< "$(bash "$IOCS_HOME/scripts/count_sites.sh" "$R"/*.s)"
    warn=$(grep -c '^file:' "$R/$u.vuln" 2>/dev/null || true)   # (grep -c prints 0 itself)
    printf '%-10s %6s %10s %10s %13s %10s %6s %8s\n' "$u" "${loc:-?}" "$fx" "$fr" "${comp:-?}" "$redir" "$syncs" "${warn:-0}" ;;
all-functions)
    grep -hoE '^\s*\.type\s+[A-Za-z_][A-Za-z0-9_.]*,\s*@function' "$R"/*.s.compiler | sed -E 's/.*\.type\s+//; s/,.*//' \
        | sort -u | tr '\n' ',' > "$R/$u.analysis"
    echo "$u: $(tr ',' '\n' < "$R/$u.analysis" | grep -c .) functions targeted" ;;
smoke)
    [ -x "$R/$u.new" ] || die "no $R/$u.new"
    one() {  # <binary> [preload] -- args : "<exit> <stdout sha>" in a fresh WORK directory
        local bin=$1 pre=$2; shift 2; local w; w=$(mktemp -d)
        ( cd "$w" && LD_PRELOAD=$pre timeout "${CHECK_TIMEOUT:-60}" "$bin" "$@" < /dev/null > "$w/out" 2> /dev/null ); local rc=$?
        echo "$rc $(sed "s#$w#WORK#g; s#$R/$u\.\(out\|new\)#PROG#g" "$w/out" | sha256sum | cut -c1-12)"; rm -rf "$w"
    }
    res=PASS; detail=""
    for a in --version --help; do
        o=$(one "$R/$u.out" "" $a); n=$(one "$R/$u.new" "$R/lib/table.so" $a)
        [ "$o" = "$n" ] && detail+=" $a:ok" || { detail+=" $a:DIFF(${o% *}/${n% *})"; res=FAIL; }
    done
    nt=$(one "$R/$u.new" "" --help); detail+=" no-table:${nt% *}"
    if [ -f "$here/$u.dta.args" ]; then
        bash "$0" "$u" check > /dev/null 2>&1 && detail+=" workload:ok" || { detail+=" workload:FAIL"; res=FAIL; }
    fi
    echo "$u $res$detail" ;;
*) die "unknown step $step" ;;
esac
