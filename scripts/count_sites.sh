#!/bin/bash
# count_sites.sh <rewritten .s>... : "<redirected> <syncs>" for the given files.
#   redirected: accesses that go through a compartment page (every *_gs macro except lea_store_gs:
#               a store also keeps its stack write, a load reads the page)
#   syncs:      lea_store_gs copies, stack -> page, after a call or a write the rewriter cannot
#               name (escaped address, indexed element, recursion); consistency, not protection
# Commented-out macros (#lea_gs) are not counted. Used by every script that reports counts.
cat "$@" 2>/dev/null | awk '/^[ \t]+lea_store_gs[ \t]/ {s++; next} /^[ \t]+[a-z_]+_gs[ \t]/ {r++} END {printf "%d %d\n", r, s}'
