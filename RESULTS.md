# Results

This file maps the evaluation of the paper (IOCS: Input-Oriented Object Compartmentalization for
Memory Damage Containment) to the commands that regenerate it. Every number below comes from a
recorded run under [`evidence/`](evidence/), made from a clean checkout; each run's `env.txt` names
the commit, tool versions and Docker images.

**Scope.** This artifact reproduces the analyses, the rewriting and the functional behaviour of
the rewritten programs. It does not reproduce performance numbers (Fig. 5, Table 2): the paper
measured them on a 32-core Intel Xeon Silver 4110 machine, which is not available here, and the runs here execute under emulation on an
Apple-silicon host (Rosetta for building and rewriting, QEMU for running), so timings would not
mean anything. What every run does establish is that each program compiles, is rewritten,
links, and behaves like the original.

| Paper item | Here | Command | Record |
|---|---|---|---|
| Fig. 3, hybrid taint call graph | Reproduced | `scripts/iocs run tiny` | `evidence/tiny/` |
| Sec. 4.2, pointer offset trees (Listing 3) | Reproduced | `IOCS_REWRITE_MODE=tree scripts/iocs run tiny` | `evidence/tiny-tree/` |
| Sec. 4.3-4.5, rewriting and run-time enforcement | Reproduced | `scripts/iocs run tiny` | `evidence/tiny/` |
| Sec. 5.2, Nginx 1.3.9 | Rewritten and tested (functional) | `scripts/iocs nginx` | `evidence/nginx/` |
| Table 1, coreutils 8.31 | Regenerated | `scripts/iocs coreutils` | `evidence/coreutils/`, `evidence/coreutils-tree/` |
| Fig. 5, Table 2, performance | Not included (see Scope) | | |
| Sec. 4.4, output verifier and proofs; Sec. 5.1, exploit replay | Not included | | |

Pre-built, tested binaries of tiny and Nginx with their `table.so` are in
[`artifacts/`](artifacts/) (`scripts/iocs artifacts test tiny|nginx`).

## Pipeline modes

The rewriter has two modes, selected with `IOCS_REWRITE_MODE`:

- **tree** (`src/ptr_offset_tree/`): the full pipeline of Sec. 4. Hybrid taint analysis selects
  the objects, and pointer offset trees lift a tainted pointer parameter to the caller object
  it points to. Stores go to the compartment only.
- **directory** (`src/rewriter/`, the default): compartmentalizes every local object of the
  functions that dynamic taint analysis observed. This is the DTA-driven setting the paper uses
  for Nginx, where SUTURE could not be run (Sec. 5.2); it protects all locals of those functions
  rather than expanding from the tainted objects by one degree.

The counts in each record: *compartments* are the compartments the rewritten code uses;
*redirected* are memory accesses rewritten to go through a compartment; *syncs* (directory mode
only) are copies from the stack to a compartment after calls and indirect writes.

## Fig. 3: hybrid taint analysis (tiny)

Dynamic taint analysis (PIN + libdft64, one `GET /` request) and SUTURE, joined by
`src/sta/hybrid_report.py`. A function counts as found by static analysis when SUTURE reports a
warning in it.

| Function | DTA calls | SUTURE warnings | Found by | Paper Fig. 3 |
|---|---|---|---|---|
| `parse_request` | 2 | 6 | both | static |
| `log_access` | 2 | 2 | both | static |
| `rio_readinitb` | 2 | 3 | both | static |
| `url_decode` | 2 | 3 | both | static |
| `writen` | 12 | 2 | both | static |
| `handle_directory_request` | 2 | 0 | DTA | dynamic |
| `rio_read` | 156 | 0 | DTA | dynamic |
| `open_listenfd`, `process`, `rio_readlineb` | 11, 2, 10 | 0 | DTA | shown, unmarked |
| `format_size` | 8 | 0 | DTA | not shown |

The static and dynamic sets match the figure. Dynamic analysis additionally observes four
functions on the same request; SUTURE finds nothing dynamic analysis misses. The result is the
same for three ways of building SUTURE's bitcode (`scripts/iocs sta-variants tiny`).

## Listing 3: pointer offset trees (tiny)

| Callee parameter | Lifted to | Paper (Listing 3) |
|---|---|---|
| `url_decode` `dest` at -48 | `process` `req` at -544 | -32 -> -560 |
| `parse_request` `req` at -4160 | `process` `req` at -544 | -4144 -> -560 |
| `rio_readinitb` `rp` at -8 | `parse_request` `rio` at -4128 | |
| `log_access` `c_addr` at -32 | `main` `clientaddr` at -288 | |

Offsets differ from the listing because the compiler here is gcc 9.5. Tree mode gives tiny 4
compartments and 19 redirected accesses; directory mode gives 72 compartments, 97 redirected
accesses and 179 syncs. In both modes the rewritten server serves files byte-identical to the
original, and without `table.so` it cannot serve a request (`tests/serve_tiny.sh`).

## Nginx 1.3.9

Built with gcc 9.4 (`-O0 -gdwarf-2`), rewritten in directory mode for the 86 request-handling
functions of the dynamic taint trace in `benchmarks/nginx/nginx.analysis` (recorded with the
original artifact; DTA is not rerun for Nginx), relinked with Nginx's own build, and served with
ApacheBench.

| | |
|---|---|
| Compartments | 458 |
| Redirected accesses / syncs | 2482 / 2095 |
| Original and IOCS binary | serve 128 KB, 1 MB and 4 MB files byte-identical, a 404, 2000 requests with 0 failures |
| IOCS binary without `table.so` | does not start |

Tree mode also runs on Nginx (`IOCS_REWRITE_MODE=tree scripts/iocs nginx`: 51 compartments, 484
redirected accesses, same serving results), but only partly: SUTURE finishes for 59 of Nginx's 79
entry functions within 20 minutes each. This is the scalability limitation the paper discusses
in Sec. 6.1.

## Table 1: coreutils 8.31

The six utilities, built from the 8.31 release with gcc 9.4, each run through the whole pipeline
on the workload in `benchmarks/coreutils/<u>.dta.args`. The rewritten program must give the
original's exit status and output on that workload, and must fail without `table.so`; all
twelve runs pass (pwd has no SUTURE-tainted object, so in tree mode it has nothing to protect).

| Utility | LoC | Functions executed (DTA) | Tree: compartments / redirected | Directory: compartments / redirected | Paper: variables / functions |
|---|---|---|---|---|---|
| basename | 190 | 14 | 2 / 9 | 4 / 11 | 5 / 1 |
| pwd | 394 | 9 | 0 / 0 | 32 / 12 | 12 / 8 |
| wc | 895 | 25 | 6 / 37 | 46 / 238 | 39 / 7 |
| cp | 1226 | 42 | 24 / 181 | 204 / 412 | 28 / 7 |
| factor | 2661 | 28 | 2 / 11 | 124 / 523 | 216 / 42 |
| ls | 5310 | 96 | 10 / 51 | 192 / 537 | 154 / 91 |

The counts depend on the workload, which the paper does not record, so they are not expected to
match it exactly. "Functions executed" includes library functions statically linked from
coreutils' `lib/`.

## All of coreutils compiles under IOCS

Beyond the six utilities of Table 1, every one of the 105 programs that coreutils 8.31 builds is
rewritten with all of its own functions compartmentalized, relinked, and run against coreutils'
own test suite (`scripts/sweep_coreutils.sh`, then `scripts/coreutils_tests.sh`; set
`SWEEP_MODE=tree` and `CUTEST_MODE=tree` for tree mode). In both modes all 105 compile, rewrite
and link, and the rewritten programs pass 403 of the 404 tests that the unmodified build passes.
The remaining test, `tests/misc/env-null`, prints the environment, which contains the test
wrapper's `LD_PRELOAD`.
