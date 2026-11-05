# IOCS: Input-Oriented Object Compartmentalization

IOCS places the program objects that untrusted input reaches into separate compartments. It
finds the functions and local objects on the input-handling path (dynamic taint analysis with
Intel PIN and libdft64, static taint analysis with SUTURE), rewrites the x86-64 assembly so that
accesses to those objects go through a compartment table addressed by `%gs`, and supplies the
table at run time as a small `LD_PRELOAD` library (`table.so`).

[RESULTS.md](RESULTS.md) maps the paper's figures and tables to the commands that regenerate
them and the recorded runs in [`evidence/`](evidence/). [NOTES.md](NOTES.md) lists the exact
dependency versions, how to install Binary Ninja, the other ways to run the pipeline, how each
evaluation is set up, and what is missing or unfinished.

## Contents

| Path | |
|---|---|
| `iocs.sh` | Pipeline driver: `./iocs.sh <target> <stage>...` |
| `src/dta/` | Dynamic taint analysis: PIN tool built on libdft64 |
| `src/sta/` | Static taint analysis: SUTURE entry-configuration generator, hybrid DTA/STA report |
| `src/rewriter/` | DWARF variable offsets, assembly analysis (Binary Ninja), compartment table, rewriting, input verifier |
| `src/ptr_offset_tree/` | Pointer offset tree analysis and its rewriter (paper Alg. 1-2); `IOCS_REWRITE_MODE=tree` |
| `benchmarks/` | `tiny.c` and the build Makefiles; `nginx/`, `coreutils/`, `exploits/` |
| `artifacts/` | Pre-built, tested binaries with their `table.so`: `tiny/`, `nginx/` |
| `evidence/` | Recorded runs: logs, summaries, reports, hashes |
| `scripts/` | `iocs`, the entry point for setup and every run; the scripts it dispatches to |
| `docker/` | The three images the scripts use |
| `third_party/` | libdft64 and SUTURE (submodules), PIN fetcher, SUTURE/LLVM 9 build, `versions.env` |
| `tests/` | Lint and runtime checks |

## 1. Test the pre-built binaries (Docker only)

`artifacts/tiny/` and `artifacts/nginx/` hold an IOCS-rewritten binary, its `lib/table.so`,
`table.c`, the original binary, `SHA256SUMS`, and `EVIDENCE` (the recorded run that built and
tested them).

```sh
scripts/iocs artifacts test tiny     # rewritten tiny web server, with and without table.so
scripts/iocs artifacts test nginx    # original vs rewritten Nginx 1.3.9, and without table.so
```

The rewritten binaries use `rdgsbase`, so the CPU and kernel must provide FSGSBASE: x86-64 Linux
5.9 or later, or the macOS QEMU VM described below. Expected output: `serve_tiny: PASS`, and for
Nginx `serve_test: PASS` for both binaries plus `does not come up without table.so (expected)`.

To run one by hand on an x86-64 Linux host (Ubuntu 22.04 for tiny, 20.04 for Nginx):

```sh
cd artifacts/tiny && LD_PRELOAD=./lib/table.so ./tiny.new 9999      # then: curl http://127.0.0.1:9999/
```

## 2. Run the full pipeline

### Requirements

- Docker with buildx and about 30 GB of free disk. On macOS, 24 GB of RAM or more: the scripts
  give the build VM 14 GB (adjustable in `config.env`).
- Binary Ninja 3.1.3469 for Linux (`BinaryNinjaLinux.zip`) and its licence file. Binary Ninja
  is commercial and not included; the image is built from your local copy and the licence is
  mounted at run time.
- Either a native x86-64 Linux host (kernel 5.9 or later, `kernel.yama.ptrace_scope=0` for PIN),
  or macOS on Apple silicon with Homebrew:
  `brew install colima docker docker-buildx qemu lima-additional-guestagents`.
  On macOS the scripts use two colima VMs and switch between them automatically: `iocs-rosetta`
  (fast x86-64 emulation through Rosetta, used for compiling, SUTURE and rewriting) and `iocs-x86`
  (QEMU, slower, but provides the ptrace PIN needs and FSGSBASE). Rosetta provides neither.

### Steps

Everything runs through one entry point, `scripts/iocs` (`scripts/iocs help` lists every command):

```sh
git clone <repository URL> IOCS && cd IOCS
cp config.env.example config.env        # set BN_LINUX_ZIP and, if needed, BN_LICENSE
scripts/iocs setup                      # submodules, VMs, images, smoke tests
scripts/iocs run tiny                   # DTA -> STA -> rewrite -> link -> runtime test
scripts/iocs sta-variants tiny          # SUTURE under three bitcode recipes
scripts/iocs nginx                      # build, rewrite, relink and serve Nginx 1.3.9
scripts/iocs coreutils                  # coreutils 8.31: basename pwd wc cp factor ls (Table 1)
scripts/sweep_coreutils.sh              # all 105 coreutils programs, every function rewritten
scripts/coreutils_tests.sh              # coreutils' test suite against the swept programs
scripts/iocs evidence                   # list the recorded runs
```

Every run takes `IOCS_REWRITE_MODE=tree` for the pointer-offset-tree mode (SUTURE's tainted
variables, lifted to the caller objects they point to), e.g. `IOCS_REWRITE_MODE=tree scripts/iocs
run tiny`; the sweep and the test suite take `SWEEP_MODE=tree` and `CUTEST_MODE=tree`.
RESULTS.md explains the two modes.

On an Apple M4 host the first `setup` spends about 26 minutes building LLVM 9 for SUTURE;
`run tiny` takes about 4 minutes, `nginx` about 4, `coreutils` about 20 (tree mode about 27),
the sweep about 10 and the test suite about 20 for each tree copy. Tree-mode Nginx runs SUTURE
once per entry function and takes several hours (`STEPS="build patch serve"` reuses a previous
SUTURE result).
`scripts/iocs artifacts export tiny|nginx` copies a run's binaries into `artifacts/` after
checking their hashes against the run's record; `scripts/iocs stage <target> <stage>...` runs
single pipeline stages in the right container, and `scripts/iocs shell` opens one.

### What gets recorded

Each scripted run writes `evidence/<run>/<UTC time>/`:

| File | Contents |
|---|---|
| `env.txt` | commit, submodule commits, tool versions, Docker image IDs |
| `<n>-<step>.log` | complete output of each step (logs over 1 MB are xz-compressed; read with `xzcat`) |
| `summary.txt` | the numbers reported in RESULTS.md |
| `hybrid-taint.txt`, `.dot` | per function: DTA calls, SUTURE entry, SUTURE warnings, propagated taint flows |
| `rewritten-sites.txt` | every rewritten access: `file:line: macro    <- original instruction` |
| `table.c`, `sha256.txt` | the compartment table, and hashes of the binaries the run built |

### Running stages by hand

`./iocs.sh <target> <stage>...` runs inside the `iocs:dev` image with the repository at `/iocs`
and the licence mounted (see `in_image` in `scripts/lib.sh`):

| Stage | Does | Needs |
|---|---|---|
| `tools` | builds the PIN tool | |
| `build` | compiles `benchmarks/<t>.c` to `result/<t>/` | |
| `dta` | runs the program under PIN; `benchmarks/<t>.dta.sh` drives it | ptrace |
| `sta` | SUTURE entry config, SUTURE, warnings, hybrid report | |
| `rewrite` | compartment table and rewritten assembly | Binary Ninja |
| `link` | `lib/table.so` and `<t>.new` | |
| `run` | `LD_PRELOAD=./lib/table.so ./<t>.new` | FSGSBASE |

## Pipeline and paper sections

| Paper | Code |
|---|---|
| 4.2 Dynamic taint analysis | `src/dta/sources/libdft-mod.cpp` (`iocs.sh dta`) |
| 4.2 Static taint analysis | `src/sta/main.py` (SUTURE entry configuration), SUTURE (`third_party/SUTURE`), `src/sta/hybrid_report.py` |
| 4.2 Static variable offset analysis | `src/rewriter/src/dwarf_analysis_old.py` (pyelftools) |
| 4.2 Pointer offset trees | `src/ptr_offset_tree/` |
| 4.3 Assembly lexical analysis | `src/rewriter/src/asm_analysis.py`, `bin_analysis.py` (Binary Ninja LLIL SSA) |
| 4.3 Compartment creation | `src/rewriter/src/gen_table.py` (writes `table.c`) |
| 4.3 Compartment relocation | `src/rewriter/src/rewriter.py` (`*_gs` macros) |
| 4.4 Static verification | `src/rewriter/src/verifier.py`, `insts.py` (input verifier) |
| 4.5 Runtime enforcement | `table.c` (generated by `gen_table.py`): page sets per thread and per signal handler, `_writegsbase_u64`, via `LD_PRELOAD` |

Binary Ninja must disassemble in AT&T syntax: `docker/binaryninja-settings.json` sets this in
the image. All versions and checksums are in `third_party/versions.env`.
