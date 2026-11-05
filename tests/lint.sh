#!/bin/bash
# Static checks that must pass on every commit of this repository. Exit 1 on any failure.
cd "$(dirname "$0")/.." || exit 2
fail=0
bad() { echo "FAIL: $*"; fail=1; }

# 1. Binary Ninja is licence-bound: no licence, installer, database or core library tracked.
git ls-files | grep -Ei '(^|/)license\.(dat|txt)$|BinaryNinja.*\.(zip|dmg)$|\.bndb$|libbinaryninjacore' \
  | while read -r f; do bad "Binary Ninja artefact tracked: $f"; done | grep . && fail=1

# 2. No absolute home-directory paths.
git grep -InE '/home/[a-z]|/Users/[a-z]' -- src benchmarks scripts docker third_party/*.sh iocs.sh tests \
    ':!tests/lint.sh' \
  | sed 's/^/  /' | grep . && bad "absolute home paths in active code (above)"

# 3. Shell scripts parse; Python compiles.
for f in iocs.sh benchmarks/*.sh benchmarks/*/*.sh scripts/*.sh third_party/*.sh tests/*.sh src/dta/sources/compile.sh; do
  [ -f "$f" ] && { bash -n "$f" || bad "bash -n $f"; }
done
#    The pipeline needs Python >= 3.10 (match statements) and < 3.13 (cgi); IOCS_PYTHON overrides.
PY=${IOCS_PYTHON:-python3}
"$PY" -c 'import sys; sys.exit(not (3,10) <= sys.version_info[:2] < (3,13))' \
  || bad "$PY is $("$PY" -V 2>&1); the pipeline needs 3.10-3.12 (set IOCS_PYTHON)"
for f in $(git ls-files 'src/*.py'); do
  "$PY" -c 'import ast,sys; ast.parse(open(sys.argv[1]).read())' "$f" 2>/dev/null || bad "syntax $f"
done

# 4. Every tracked gitlink is declared in .gitmodules.
git ls-files -s | awk '$1=="160000"{print $4}' | while read -r p; do
  git config -f .gitmodules --get-regexp '\.path$' | awk '{print $2}' | grep -qxF "$p" || echo "undeclared submodule $p"
done | grep . && fail=1

[ $fail -eq 0 ] && echo "lint: OK"
exit $fail
