# Pointer offset tree analysis (paper Sec. 4.2, Listing 3, Algorithms 1-2)

This directory holds the tree-mode rewriter (`IOCS_REWRITE_MODE=tree`): the static analysis that
builds call trees between the functions on the input path (`Gen_Fun_Trees`) and then pointer offset
trees that map a callee's pointer parameter back to the caller's object it aliases
(`Gen_Ptr_Offset_Trees`), so a compartment is assigned to the object where it is defined rather than
to each pointer copy. Unlike directory mode (`src/rewriter`), tree mode compartmentalises only the
SUTURE-tainted variables (plus whatever the trees lift), and a store **replaces** the stack write
(true isolation), so a tainted object lives only in its `%gs` page.

| File | |
|---|---|
| `sta/taint_analysis.py` | `FunctionNode`, `PtrOffsetTreeNode`, `PtrOffsetTree`; one summary per function, trees built from the summaries (`process_offset`) |
| `asm_rewriter/main.py` | the driver: DWARF, SUTURE taints, pointer offset trees, `trees.txt`, table, rewriting |
| `asm_rewriter/src/` | the same modules as `src/rewriter/src/`, at this version; `gen_table.py` and `rewriter.py` carry the tree-mode changes (compartment sizes, stack-only exceptions) |

## Pipeline (one path for every input)

`main.py` takes the linked program and rewrites each object that defines a function with a
compartment:

```
main.py --binary <program>.out [--directory <dir of .s/.o/.intel>] [--result <SUTURE inputs + table.c>]
```

1. DWARF of every analysed function is read from the linked program; SUTURE's tainted variables
   (`<t>.vuln`) are marked on it. A tainted function need not be in the DTA list (`<t>.analysis`):
   its variables are still recorded and either lifted into a caller's object or isolated in place.
2. Pointer offset trees are built on the linked program (so a tree can cross object boundaries) and
   written to `<result>/trees.txt` in the form of the paper's Listing 3, with the function
   summaries. An argument makes an alias edge only when it *is* the address of a frame object: a
   `lea` of the object (plus a constant), a callee's spilled pointer parameter passed on that still
   points into what its callers passed (its frame slot written only by the prologue's spill and by
   steps from its own value, `p++`, `p += n`, which in C stay in the object; its address never
   taken: a parameter reassigned from anything else before the call, `p = loc; sink(p)`, passes
   something else), or a local pointer whose
   only assignment is such a `lea` (`struct stat st; struct stat *sbuf = &st`: the root is `st`, its
   whole extent). A value loaded through a pointer (`foo(p->field)`) is no edge, and an edge needs
   the callee parameter to be a pointer. Arguments are matched to DWARF parameters by where they
   are passed, not by position: `dwarf_analysis_old.abi_param_locations` classifies each parameter
   by the SysV x86-64 rules (a hidden result pointer in `%rdi` for a struct or union returned in
   memory; `float`/`double` in `%xmm`, `long double` and structs over 16 bytes on the stack, a
   16-byte struct in two registers), and the argument Binary Ninja passes in that register or
   stack slot is the parameter's. A pointer parameter whose argument is not found (an untyped
   call's stack argument, a type it cannot classify) is not resolved.
3. Lifts (`lifted.txt`). For each tainted pointer parameter, `resolve_param` follows **every** call
   of its function in the program (and through parameters passed on, their callers) to the caller
   objects it can point to. Its own slot is dropped only when every call resolves and every one of
   those objects can be compartmentalised; each object gets a compartment. Otherwise
   (`own slot: ... (why)`) it keeps its own slot, and the objects that can be isolated are isolated
   too. Its function's address being taken, the parameter being reassigned (other than stepped) in
   its own function, a call passing anything else, or a caller object that must stay on the stack
   (below) all keep the callee's slot. Whether a variable can have a compartment is decided
   **before** lifting.
4. One compartment table (`table.c`) for the variables that get one; a struct object gets one slot
   sized to the whole object, a scalar/pointer one word. A variable kept on the stack has no entry.
5. Binary Ninja info is taken once from the linked program and reused for every object.
6. Each object's `.s` is rewritten in place and reassembled to its `.o`, so the program's own make
   relinks without recompiling any C. If the rewritten code still reaches a slot on the stack
   (`tree_uncovered`), that slot stays on the stack, the lifts are decided again and every object is
   rewritten from its original (each round moves at least one slot; it ends).
7. `compartments.txt`: the compartments are the slots the rewritten code uses; the table's unused,
   placeholder (no compartment at all) and padding slots are listed apart. The counts of every
   script (`coreutils.sh counts`, the sweep, `run_nginx.sh`, `run.sh`) report this number.

Since a store replaces the stack write, the page is the only current copy: every access to a
compartment's bytes must go through it. A variable therefore stays on the stack (no compartment)
when that cannot be guaranteed, logged as
`consistency: <fun>: <slot> stays on the stack (<reason>: <instruction>)` (`tree_stack_only` in
`rewriter.py`, `StackOnly` in `main.py`; also `kept on stack:` in `lifted.txt`):

| reason | |
|---|---|
| `recursive` | the function can re-enter itself on one thread (a page is per variable, not per activation) |
| `indexed` | an access with an index register (`-144(%rbp,%rax,8)`) |
| `form` | an instruction with no macro (`movsbl`, `cmov`, x87, three-operand `imul`, ...) |
| `interior` | an access inside a scalar's bytes, or a non-`mov`/`lea` inside an aggregate |
| `one-past` | a `lea` of an aggregate's end (`buf + sizeof buf`) when no variable starts there |
| `r10/r11` | an access where the function keeps a value of its own in the macros' scratch registers (from its first to its last use, plus loops back into that span; e.g. the stack-clash probe) |
| `frame-pointer` | the function copies or computes with `%rbp` itself (not the prologue/epilogue): any slot can be reached through that register |
| `frame-anchor` | a `lea` of a frame address that lies in no variable, or at or above the top of the local area (below the callee-saved pushes): gcc indexes a multi-dimensional array from such an anchor (`leaq -16(%rbp),%rsi; addq %rsi,%rax; subq $32,%rax; movl %ecx,(%rax)` is `alt[i][0]`), so every slot of the function stays on the stack. Not anchors: the epilogue's `leaq -N(%rbp),%rsp`, and `va_start`'s register save area and stack-argument addresses stored straight into the `va_list` (`va_arg` stays inside those areas, which hold no variable). A struct-return temporary (`leaq -224(%rbp),%rdi; call scan_arg`) counts as an anchor too |
| `stack-passed`, `no-slot`, `no-code` | a parameter the caller passes on the stack, a variable with no frame slot, a function outside the rewritten objects |
| `unredirected` | after the rewrite, an executed original instruction still touches the slot's bytes (`tree_uncovered`); the slot goes to the stack and the next round starts |

`tree_uncovered` is exact: every executed instruction other than a page macro whose frame operand
touches a compartmentalised slot's bytes is reported, and an executed frame anchor reports every
slot of its function. A verifier copy counts as executed when a label inside it can be jumped to. The rewriter emits no executed copy of a
replaced instruction: a load, a read-modify-write (`add`/`sub`/`imul`/`shl`/`and`_store_gs) or a
`movss`/`movsd` store keeps the original only as a comment (`#<instruction>`), and a `mov` store or
a `lea` keeps it after `jmp verifier_metadata_N` (never executed).

Members and constant-index elements of an aggregate's slot are reached with `mov_mem_{store,load}_gs`
and `lea_mem_gs` (slot + displacement, added with `lea` so the flags survive). A spilled formal
parameter (below `%rbp`) gets a slot like a local when it is tainted and no tree lifts it; one passed
on the stack does not. The replaced original kept for the verifier is skipped with a plain `jmp`
(flag-neutral).

`IOCS_DEBUG_STOP=552` stops after the tree pass (trees and summaries are in `trees.txt`).

## Runs

The six Table 1 utilities, end to end from a clean checkout (build VM and run VM switched as
needed): build, migrate, bitcode of every object (llvm-linked), DTA, STA + SUTURE, tree rewrite,
relink, check, counts, into `build/tree/result/<u>/`; evidence in `evidence/coreutils-tree/`:

```sh
IOCS_REWRITE_MODE=tree scripts/run_coreutils.sh [utility...]
```

All 105 coreutils programs (migrate, `all-functions` as the target set, bitcode of every object,
STA + SUTURE, tree rewrite, relink, smoke; `build/tree-sweep/result`,
`evidence/coreutils-tree-sweep/`), then their test suite against the original's:

```sh
SWEEP_MODE=tree scripts/sweep_coreutils.sh
SWEEP_MODE=tree SWEEP_STEPS="rewrite link smoke" scripts/sweep_coreutils.sh   # keep SUTURE's results
CUTEST_MODE=tree REUSE_ORIG=1 scripts/coreutils_tests.sh
```

tiny (`result/tiny`, `evidence/tiny-tree/`; the check is `tests/serve_tiny.sh` on the run VM):

```sh
IOCS_REWRITE_MODE=tree scripts/run.sh tiny
```

Nginx (`scripts/run_nginx.sh`: build -> bitcode -> SUTURE -> tree rewrite -> relink -> serve;
`evidence/nginx-tree/`). Every analysis input is `build/nginx/nginx.orig`, the binary as built
(`objs/nginx` is a rewritten binary after any relink). The SUTURE entry config is every function of
`benchmarks/nginx/nginx.analysis` with all parameters (79 entries). SUTURE analyses an entry's calls
context-sensitively: one run of all of them did not finish its first entry (`ngx_conf_parse`) in an
hour. `benchmarks/nginx/suture_split.sh` (`nginx.sh nginx sta_split`, the default) runs SUTURE once
per entry, `SUTURE_JOBS` at a time, each for at most `SUTURE_ENTRY_TIMEOUT` seconds (1200), keeps only
the warning part of each log, and merges the warnings of the entries that finish
(`suture-entries.txt`: status, time and warnings per entry; taint that needs two entries in
sequence is not found). `NGINX_STA=whole` runs the single SUTURE run instead (`SUTURE_TIMEOUT`).
`STEPS` runs part of the flow, and a later run reuses `build/tree/result/nginx`:

```sh
IOCS_REWRITE_MODE=tree STEPS="build sta" scripts/run_nginx.sh        # build VM only
IOCS_REWRITE_MODE=tree STEPS="build patch serve" scripts/run_nginx.sh
```

The relink also rebuilds `table.so` in iocs-nginx-build:20.04 in tree mode (the tree table links
against glibc symbols newer than Nginx's 2.31 when built in iocs:dev); directory mode keeps the
`table.so` of `nginx.sh patch`.

By hand (iocs:dev; iocs-suture:llvm9 for the llvm-link):

```sh
IOCS_RESULT_DIR=/iocs/build/tree/result NGINX_HOME=/iocs/build/nginx/nginx-1.3.9 \
    bash benchmarks/nginx/nginx.sh nginx bitcode     # iocs:dev   (SUTURE clang 9, one .bc per object)
... nginx.sh nginx bclink                            # iocs-suture:llvm9 (has llvm-link)
... nginx.sh nginx sta_split                         # iocs:dev   (SUTURE per entry; entry config = every DTA function, all params)
IOCS_REWRITE_MODE=tree ... nginx.sh nginx patch      # iocs:dev   (tree rewrite of objs/src/**/*.s)
```
