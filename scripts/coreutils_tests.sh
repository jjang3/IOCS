#!/bin/bash
# Run coreutils' own test suite against the rewritten programs of a sweep (scripts/sweep_coreutils.sh)
# and compare every test's result with the same suite on the unmodified tree.
#   scripts/coreutils_tests.sh            (run VM: the rewritten programs need FSGSBASE)
#   CUTEST_MODE=tree scripts/coreutils_tests.sh   the tree-mode sweep's programs (SWEEP_MODE=tree
#   scripts/sweep_coreutils.sh: build/tree-sweep/result), the same as
#   CUTEST_RESULT=build/tree-sweep/result; CUTEST_RESULT=<dir> takes any sweep's programs. Its copy of
#   the tree is build/cutest/<CUTEST_NAME> (default: iocs, or tree for build/tree-sweep/result), so
#   the runs of the two modes are kept side by side. REUSE_ORIG=1 reuses a finished orig/ run.
# Two copies of the built tree under build/cutest/: orig/ as built; iocs/ where every src/<u> that the
# sweep rewrote is a wrapper that preloads that program's own table.so and runs <u>.new
# (a C wrapper: execv(<u>.new, argv) with LD_PRELOAD=<its table.so>, so argv[0] is the caller's).
# Both run "make check SUBDIRS=." (tests/, not gnulib-tests) as an unprivileged user, TEST_JOBS in
# parallel. Before that, every rewritten program gets the sweep's smoke test (coreutils.sh smoke).
# CUTEST_TESTS="tests/misc/wc.sh ..." runs only those tests (with REUSE_ORIG=1: to re-check a fix).
# Evidence: evidence/coreutils-tests/<UTC stamp>/: tests.txt (per test: orig, iocs), smoke.txt,
# summary.txt, the failing tests' logs (logs/).
. "$(dirname "$0")/lib.sh"
HCU=$IOCS_HOME/build/coreutils/coreutils-$COREUTILS_VERSION
case ${CUTEST_MODE:-directory} in tree) DEF=build/tree-sweep/result ;; directory) DEF=build/sweep/result ;; *) die "CUTEST_MODE: directory or tree" ;; esac
RES=${CUTEST_RESULT:-$DEF}; RES=${RES#/iocs/}; RES=${RES#$IOCS_HOME/}; HSW=$IOCS_HOME/$RES; SW=/iocs/$RES
case $RES in build/tree-sweep/*) NAME=${CUTEST_NAME:-tree} ;; *) NAME=${CUTEST_NAME:-iocs} ;; esac
[ "$NAME" != orig ] || die "CUTEST_NAME orig is the unmodified tree's copy"
[ -x "$HCU/src/ls" ] || die "coreutils tree not built"
ls "$HSW"/*/*.new > /dev/null 2>&1 || die "no rewritten programs in $RES (run scripts/sweep_coreutils.sh)"
evidence_start coreutils-tests
echo "programs:   $RES (tree copy build/cutest/$NAME)" >> "$EVID/env.txt"
use_vm run; ev_images
ev_run 1-smoke in_image iocs-nginx-build:20.04 env COREUTILS_HOME=/iocs/build/coreutils/coreutils-$COREUTILS_VERSION \
    IOCS_RESULT_DIR=$SW bash -c \
    'for d in '"$RES"'/*/; do u=$(basename "$d"); [ -x "$d/$u.new" ] && echo "SMOKE $(bash benchmarks/coreutils/coreutils.sh "$u" smoke 2>&1 | tail -1)"; done'
sed -n 's/^SMOKE //p' "$EVID/1-smoke.log" > "$EVID/smoke.txt"
ev_run 2-suite in_image iocs-nginx-build:20.04 env CUTEST_TESTS="${CUTEST_TESTS:-}" bash -c '
    set -u; V='"$COREUTILS_VERSION"'; T=/iocs/build/cutest
    # REUSE_ORIG=1 keeps a finished orig/ run (the unmodified tree gives the same results each time).
    N='"$NAME"'
    sides="orig $N"; if [ -n "'"${REUSE_ORIG:-}"'" ] && [ -f $T/orig.check.log ]; then sides=$N; else rm -rf $T/orig; fi
    rm -rf $T/$N; mkdir -p $T
    for t in $sides; do cp -a /iocs/build/coreutils/coreutils-$V $T/$t; rm -f $T/$t/tests/*.log $T/$t/tests/*/*.log $T/$t/tests/*/*.trs
        # The Makefile names the tree it was configured in (abs_top_builddir), and the Perl tests run
        # $abs_top_builddir/src/<u>: point it at this copy, or they test the original programs.
        sed -i.orig "s#/iocs/build/coreutils/coreutils-$V#$T/$t#g" $T/$t/Makefile && touch -r $T/$t/Makefile.orig $T/$t/Makefile && rm $T/$t/Makefile.orig
    done
    # A rewritten program that hangs would stall make check forever: kill any running for 300 s.
    ( while :; do sleep 30; ps -eo pid=,etimes=,args= | awk '"'"'$2 > 300 && $3 ~ /\.new$/ {print $1}'"'"' | xargs -r kill -9; done ) &
    cat > $T/wrapper.c <<"C"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    const char *old = getenv("LD_PRELOAD");
    char *buf = malloc(strlen(TABLE) + (old ? strlen(old) : 0) + 2), *keep = old ? strdup(old) : NULL;
    strcpy(buf, TABLE);
    for (char *x = keep ? strtok(keep, " :") : NULL; x; x = strtok(NULL, " :")) {
        size_t n = strlen(x);
        if (n >= 13 && strcmp(x + n - 13, "/lib/table.so") == 0) continue;
        strcat(buf, " "); strcat(buf, x);
    }
    setenv("LD_PRELOAD", buf, 1);
    execv(PROG, argv);
    perror(PROG);
    return 127;
}
C
    n=0; for d in '"$SW"'/*/; do u=$(basename $d)
        [ -x $d/$u.new ] && [ -f $d/lib/table.so ] && [ -f $T/$N/src/$u ] || continue
        # A C wrapper, so the program sees the argv[0] of its caller (coreutils prints it in messages; a
        # script cannot pass it on). It sets LD_PRELOAD to the table.so of this program, drops a table.so
        # of another program inherited from a parent, keeps other preloads (libstdbuf.so).
        # A program that finds a helper next to its own executable (/proc/self/exe: stdbuf loads
        # libstdbuf.so from its directory) finds the tree copy'"'"'s next to <u>.new too.
        for so in $T/$N/src/*.so; do [ -f "$so" ] && ln -sfn "$so" "$d/$(basename "$so")"; done
        gcc -O1 -o $T/$N/src/$u.w -DTABLE="\"$d/lib/table.so\"" -DPROG="\"$d/$u.new\"" $T/wrapper.c || exit 1
        touch -r $T/$N/src/$u $T/$N/src/$u.w; mv $T/$N/src/$u.w $T/$N/src/$u; chmod +x $T/$N/src/$u; n=$((n+1))
    done; echo "wrapped $n programs"
    useradd -m tester 2>/dev/null; chown -R tester $T
    for t in $sides; do
        echo "== $t"; su tester -c "cd $T/$t && make -k -j'"${TEST_JOBS:-4}"' check SUBDIRS=. VERBOSE=no \${CUTEST_TESTS:+TESTS=\"\$CUTEST_TESTS\"} > $T/$t.check.log 2>&1"; echo "make check ($t) rc=$?"
        grep -E "^# (TOTAL|PASS|SKIP|XFAIL|FAIL|XPASS|ERROR):" $T/$t.check.log
    done'
# Per-test comparison.
T=$IOCS_HOME/build/cutest
res() { find "$T/$1/tests" -name '*.trs' | while read -r f; do echo "${f#$T/$1/} $(sed -n 's/^:test-result: //p' "$f" | head -1)"; done | sed 's/\.trs / /' | sort; }
join -a1 -a2 -e missing -o 0,1.2,2.2 <(res orig) <(res "$NAME") > "$EVID/tests.txt"
mkdir -p "$EVID/logs"
awk '$2 != $3' "$EVID/tests.txt" | while read -r t a b; do [ -f "$T/$NAME/$t.log" ] && cp "$T/$NAME/$t.log" "$EVID/logs/$(echo "$t" | tr / _).log"; done
ev_summary "programs smoke-tested: $(wc -l < "$EVID/smoke.txt" | tr -d ' '), PASS $(grep -c ' PASS' "$EVID/smoke.txt" || true)"
ev_summary "tests: $(wc -l < "$EVID/tests.txt" | tr -d ' '); orig PASS $(awk '$2=="PASS"' "$EVID/tests.txt" | wc -l | tr -d ' '), $NAME PASS $(awk '$3=="PASS"' "$EVID/tests.txt" | wc -l | tr -d ' ')"
ev_summary "same result: $(awk '$2==$3' "$EVID/tests.txt" | wc -l | tr -d ' '); orig PASS but $NAME not: $(awk '$2=="PASS" && $3!="PASS"' "$EVID/tests.txt" | wc -l | tr -d ' ')"
awk '$2=="PASS" && $3!="PASS" {print "  " $1 " " $3}' "$EVID/tests.txt" | tee -a "$EVID/summary.txt" >&2
ev_finalize
