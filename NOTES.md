# Notes: dependencies, installation, evaluation setups, known gaps

README.md is the quick start and RESULTS.md the paper's results. This file records the details
those leave out: the exact version of every dependency and where it is pinned, how to install
Binary Ninja, the ways to run the pipeline, how each evaluation is set up, and what is missing,
unfinished or undocumented.

## 1. Dependencies

All versions are pinned in `third_party/versions.env`, which the scripts and Dockerfiles read.
Nothing is taken from a "latest" release.

| Component | Version | Source and pin | How it is obtained |
|---|---|---|---|
| LLVM / clang (for SUTURE) | 9.0.1 (llvm-mirror `release_90`: llvm `c2f5309b`, clang `bed37d4b`) | `LLVM_MIRROR_*_SHA` | built from source by `third_party/build_suture.sh` (Release with assertions, X86 target only) into image `iocs-suture:llvm9` |
| SUTURE | `6c113b0e` (README-only commits on top of `7036d64`) | submodule `third_party/SUTURE` (github.com/seclab-ucr/SUTURE), `SUTURE_SHA` | built by `third_party/build_suture.sh`; SUTURE's EntryPointIdentifier helper fails to link and is not needed (IOCS writes SUTURE's entry configuration itself, `src/sta/`) |
| Intel PIN | 3.27 (`pin-3.27-98718-gbeaa5d51e-gcc-linux`) | `PIN_URL`, `PIN_SHA256` (`e7d44d25…7707`) | downloaded and checksummed by `third_party/get_pin.sh` (PIN cannot be redistributed) |
| libdft64 | `066c9d8b` | submodule `third_party/libdft64` (github.com/AngoraFuzzer/libdft64), `LIBDFT64_SHA` | built with the PIN tool: `./iocs.sh <t> tools` |
| Binary Ninja | 3.1.3469, Linux build, headless Python API | `BINARYNINJA_VERSION` | commercial, supplied by you; see section 2 |
| pyelftools | 0.29 | `PYELFTOOLS_VERSION` | `pip install` in image `iocs:dev` |
| termcolor | 2.4.0 | `TERMCOLOR_VERSION` | `pip install` in image `iocs:dev` |
| Python | 3.10 (Ubuntu 22.04); the code needs 3.10 to 3.12 | `docker/Dockerfile` | image `iocs:dev` |
| GNU coreutils | 8.31 release tarball | `COREUTILS_SHA256` (`ff7a9c91…e9fd`) | downloaded and checksummed by `benchmarks/coreutils/build_coreutils.sh` |
| Nginx | 1.3.9 | `NGINX_SHA256` (`30463a86…48df`) | downloaded and checksummed by `benchmarks/nginx/build_nginx.sh`, patched with `benchmarks/nginx/patches/` |
| Bropper (exploit tool) | submodule `benchmarks/exploits/bropper_ex_2/Bropper` | github.com/Hakumarachi/Bropper | only for the exploit material (section 4) |

The scripts build three Docker images (all `linux/amd64`):

| Image | Base | Contents | Used for |
|---|---|---|---|
| `iocs-suture:llvm9` | Ubuntu 20.04 | LLVM/clang 9 and SUTURE | building `iocs:dev`; `llvm-link` for Nginx's bitcode |
| `iocs:dev` | Ubuntu 22.04 | gcc 9.5 as `gcc`, Python 3.10, pyelftools, PIN, SUTURE and its clang 9, Binary Ninja | every pipeline stage; tiny is compiled and run here |
| `iocs-nginx-build:20.04` | Ubuntu 20.04 | gcc 9.4, glibc 2.31, OpenSSL 1.1, ApacheBench | compiling, relinking and running Nginx and coreutils. Nginx 1.3.9 does not build against glibc 2.32 or later, and the paper's binaries were built with gcc 9.4. |

`env.txt` in every recorded run lists the commit, the submodule commits, the versions above and
the Docker image IDs used.

## 2. Binary Ninja

Binary Ninja is commercial and is never part of this repository. You need two files:

- **`BinaryNinjaLinux.zip`** for version **3.1.3469** (the Linux build, even on macOS: it runs
  inside the Docker image). The zip used for the recorded runs has SHA-256
  `456afa5c802d54d466efdee4c755752a1e5e79b0a53fd826f96baf615bebe9fe`.
- **The licence file** (`license.dat`; it may come as `license.txt`, with the same content). The
  licence must allow the headless Python API, because every script loads binaries headlessly.

Steps:

1. Put the zip anywhere outside the repository, and in `config.env` set
   `BN_LINUX_ZIP=/path/to/BinaryNinjaLinux.zip`. The file must have exactly that name.
2. Put the licence where the scripts look by default, or point `BN_LICENSE` at it:
   - macOS: `~/Library/Application Support/Binary Ninja/license.dat`
   - Linux: `~/.binaryninja/license.dat`

   A `license.txt` can be copied to that path under the name `license.dat`, or used directly
   with `BN_LICENSE=/path/to/license.txt`.
3. Run `scripts/iocs setup`. `scripts/build_images.sh` unzips Binary Ninja into
   `/opt/binaryninja` inside `iocs:dev` (from a local build context; the zip is not copied into
   the repository) and installs `docker/binaryninja-settings.json` as
   `/root/.binaryninja/settings.json`. Every container gets the licence bind-mounted read-only
   at `/root/.binaryninja/license.dat`; it is never baked into an image.
4. The setup smoke test loads a binary headlessly; if the licence is missing or not accepted,
   it fails there. Binary Ninja 3.1's licence query functions report 0 or empty strings in
   headless mode even with a valid licence, so they are not a check; a successful load is.

Rules that matter:

- **Version 3.1.3469 exactly.** Do not let Binary Ninja update itself: the rewriters use its
  LLIL/MLIL Python API, which changes between releases, and only 3.1.3469 is tested.
- **AT&T syntax.** The rewriters match Binary Ninja's disassembly text against gcc's AT&T
  assembly. Binary Ninja 3.1 ignores the per-load option `arch.x86.disassembly.syntax` and needs
  the user-level setting that `docker/binaryninja-settings.json` provides. Without it Binary
  Ninja prints Intel syntax and nothing is ever rewritten (0 patches, no error).
- **Never push `iocs:dev`** to a registry: it contains Binary Ninja.
- The macOS desktop application (`BinaryNinja.dmg`) is not needed. To use the Python API outside
  Docker, put the build's `python/` directory on `PYTHONPATH` (the Linux zip unpacks to
  `binaryninja/python`); the scripts do not do this.

## 3. Ways to run it

**A. macOS on Apple silicon (the tested setup).** Install
`brew install colima docker docker-buildx qemu lima-additional-guestagents`, copy
`config.env.example` to `config.env`, set the Binary Ninja paths, and run `scripts/iocs setup`.
It creates two colima VMs and switches between them automatically, one at a time:

| VM | Type | Size (default) | Why |
|---|---|---|---|
| `iocs-rosetta` | aarch64, Virtualization.framework, Rosetta for x86-64 | 8 CPUs, 14 GB RAM, 80 GB disk | fast: compiling, SUTURE, Binary Ninja, rewriting. Rosetta provides neither ptrace (PIN) nor FSGSBASE (rewritten binaries die with SIGILL), so nothing runs here. |
| `iocs-x86` | x86_64 under QEMU | 4 CPUs, 8 GB RAM, 60 GB disk | slow, but provides ptrace for PIN and FSGSBASE for the rewritten binaries; `kernel.yama.ptrace_scope` is set to 0 after each start |

You need 24 GB of RAM (the VMs do not fit in memory together) and at least 30 GB of free disk;
a tree-mode Nginx run needs more (SUTURE's logs). The first setup spends about 26 minutes
building LLVM 9. The sizes are set in `config.env` (`BUILD_PROFILE_ARGS`, `RUN_PROFILE_ARGS`).
Always run the scripts with bash (`scripts/iocs` or `bash scripts/...`): the VM switching
breaks under zsh.

**B. Native x86-64 Linux.** Docker with buildx, kernel 5.9 or later (FSGSBASE), and
`sudo sysctl -w kernel.yama.ptrace_scope=0` for PIN. The scripts detect Linux and use one
Docker daemon (`IOCS_HOST=linux`, `IOCS_DOCKER_CONTEXT`). This path has not been run end to end;
it is the one for performance measurements.

**C. Without Docker.** `third_party/get_pin.sh` and `third_party/build_suture.sh` install PIN and
SUTURE/LLVM 9 under `third_party/`, where `iocs.sh` looks for them by default;
`pip install pyelftools==0.29 termcolor==2.4.0`, Binary Ninja's `python/` on `PYTHONPATH`, the
settings file at `~/.binaryninja/settings.json`, and gcc 9 as `gcc`. `iocs.sh` then runs the
stages directly. This path has not been run end to end.

**D. Pre-built binaries only.** `scripts/iocs artifacts test tiny|nginx` needs only Docker and a
host with FSGSBASE (the QEMU VM on macOS).

Single stages: `scripts/iocs stage <target> <stage>...` runs `iocs.sh` stages in the right
container and VM; `scripts/iocs shell` opens a shell in `iocs:dev`. `tests/lint.sh` checks the
scripts and Python sources (set `IOCS_PYTHON` to a Python 3.10 to 3.12).

## 4. Evaluation setups

**tiny** (the server application of the paper's evaluation; Fig. 3, Listing 3).
`benchmarks/tiny.c`, compiled with `benchmarks/Makefile` (`-O0 -gdwarf-2 -save-temps=obj`).
DTA drives it with one `GET /` request (`benchmarks/tiny.dta.sh`). The runtime check
`tests/serve_tiny.sh` serves an index page, a 300000-byte file, a directory listing and a 404,
makes 200 sequential requests, and checks that without `table.so` no request is served.
Command: `scripts/iocs run tiny` (tree mode: `IOCS_REWRITE_MODE=tree scripts/iocs run tiny`).

**coreutils 8.31** (Table 1). `benchmarks/coreutils/build_coreutils.sh` configures with
`FORCE_UNSAFE_CONFIGURE=1 --disable-nls --without-gmp --without-selinux` and
`CFLAGS="-O0 -gdwarf-2 -save-temps=obj"`, builds once with `-masm=intel` for the input verifier's
`.intel` files, then normally. `benchmarks/coreutils/coreutils.sh <u> <step>` holds the
per-utility steps (migrate, bitcode, link, check, counts). The DTA workloads are in
`benchmarks/coreutils/<u>.dta.args`; the paper does not record its workloads, so these are new.
Command: `scripts/iocs coreutils [utility...]` (default: the six of Table 1). The sweep over all
105 programs is `scripts/sweep_coreutils.sh`. The test-suite comparison is
`scripts/coreutils_tests.sh`: it copies the built tree twice, replaces every program in one copy
by a small C wrapper that runs the rewritten program with its own `table.so` (keeping `argv[0]`),
and runs `make check` in both copies as an unprivileged user.

**Nginx 1.3.9** (Sec. 5.2). `benchmarks/nginx/build_nginx.sh` builds it in `iocs-nginx-build:20.04`
with `-O0 -gdwarf-2 -save-temps=obj` (`benchmarks/nginx/patches/nginx-1.3.9-crypt_r.patch` for libxcrypt,
and the `-Werror` flag removed from `objs/Makefile`). The protected functions come from `benchmarks/nginx/nginx.analysis`,
a dynamic taint trace of 86 request-handling functions recorded with the original artifact; DTA
is not rerun for Nginx. `benchmarks/nginx/serve_test.sh` serves 128 KB, 1 MB and 4 MB files and a
404 and runs `ab -n 2000 -c 4`, for the original binary, the IOCS binary with `table.so`, and the
IOCS binary without it. Command: `scripts/iocs nginx`. Tree mode
(`IOCS_REWRITE_MODE=tree scripts/run_nginx.sh`) also builds Nginx's bitcode with SUTURE's clang
(`benchmarks/nginx/bitcode_cc.sh`, `nginx.sh nginx bclink`) and runs SUTURE once per entry
function (`benchmarks/nginx/suture_split.sh`, 20 minutes each, resumable), which takes several
hours; `STEPS="build patch serve"` reuses a previous SUTURE result.

**Microbenchmarks** (Table 2). Not in this repository: the sources were never committed to any
IOCS repository. They evaluate heap objects, placed into compartments through a custom `malloc()`
wrapper, and heap-object compartmentalization itself is not implemented in this code base either
(see section 5).

**CVE and exploit cases** (Sec. 5.1). `benchmarks/exploits/` holds the material as it was, not
rerun and not connected to `scripts/iocs`:

- `bropper_ex_2/`: a blind-ROP challenge server (`orig/`: source and Dockerfile) and the
  Bropper tool (submodule). `new/` holds `ibcs.new`, a rewritten binary built with an earlier
  version of the pipeline, and a Dockerfile around it; its README refers to that earlier
  pipeline's script names (`ibcs.sh`, `$HOME/IBCS/results`). To redo it with this pipeline,
  rewrite `orig/chall_fork.c` like tiny and replace `ibcs.new`.
- `nginx/`: a Dockerfile (Ubuntu 16.04, gcc 4.8) for an Nginx vulnerable to CVE-2013-2028
  (chunked transfer-encoding overflow), exercised with Metasploit's `nginx_chunked_size` module
  (links in `benchmarks/exploits/README.md`).

## 5. Missing, unfinished or undocumented

Not included:

- **Performance (Fig. 5, Table 2).** The paper's numbers come from a 32-core Intel Xeon Silver
  4110; no such machine was available, and the runs here are emulated, so none of their timings
  are performance results. Directory mode adds stack-to-compartment copies after calls (*syncs*
  in RESULTS.md), so timings measured with this code would not be comparable with the paper's.
- **Heap objects.** Only stack objects are compartmentalized; the heap containment described in
  Sec. 4 (and the custom `malloc()` wrapper of the microbenchmarks) is not in this code base.
- **Microbenchmark sources** (above).
- **Static verification (Sec. 4.4).** The input verifier (`src/rewriter/src/verifier.py`,
  `insts.py`) runs before rewriting, but the pipeline ignores its result: on tiny it flags two
  instructions gcc emitted with `%r9`, a register the design reserves. The output verifier and
  the Isabelle/HOL development are not included.
- **The original Nginx taint configuration** (`nginx_taint.conf`, referenced by
  `benchmarks/nginx/nginx_command`, a gdb helper from the original artifact) is not available;
  only the function list `nginx.analysis` is.

Limits of the current code:

- **Recursion.** Each variable has one compartment per thread, shared by a recursive function's
  activations. Directory mode copies the stack values back after a call that can re-enter the
  function; tree mode leaves such variables on the stack. A `longjmp` out of a recursive
  activation is not handled.
- **Threads and signals.** `table.so` gives each thread created through `pthread_create`, and
  each signal-handler nesting level up to four, its own compartments. Threads created any other
  way (raw `clone`, glibc-internal helper threads) share their creator's.
- **Tree mode: kept on the stack.** A variable whose accesses cannot all be redirected keeps no
  compartment; the reason is logged in `kept-on-stack.txt` (recursive function, a pointer argument
  passed on the stack, an instruction form with no macro such as `cmov` or x87, a frame address
  computed by gcc). Pointer parameters are lifted only when provably safe, so cp, ls, wc and
  Nginx have no lifts.
- **SUTURE on large programs.** For Nginx, 59 of 79 entry functions finish within 20 minutes;
  coreutils' `tsort` does not finish within 30 minutes and has no taint.
- **Directory mode leaves on the stack** accesses wider than their compartment (struct copies
  over packed members) and indexed array-element operands (logged).
- **`IOCS_REWRITE_MODE=binary`**, a third rewrite path of `src/rewriter` (SUTURE-filtered
  variables, no pointer offset trees), predates tree mode and is not used by any script.

Environment notes:

- Rewritten binaries need FSGSBASE: Linux 5.9 or later on x86-64, or the QEMU VM. Under Rosetta
  they die with SIGILL.
- `table.so` must be built against the glibc of the system the program runs on (it uses
  `pthread_create` and `dlsym`); the scripts build it in the program's runtime image.
- coreutils' test suite has 171 tests that skip and 41 that fail with the unmodified programs in
  this container environment (root-only, filesystem and timing tests). `tests/misc/env-null`
  fails only with the wrapper, because the wrapper's `LD_PRELOAD` appears in `env -0`'s output.
