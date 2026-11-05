#!/usr/bin/env python3
"""Hybrid taint report: which functions dynamic (DTA) and static (SUTURE) taint analysis find.

    python3 hybrid_report.py <result dir> [<target>]      e.g. result/tiny tiny

Reads, from <result dir>:
  <t>.analysis  DTA trace from the PIN tool (comma-separated names of executed calls)
  <t>.config    SUTURE entry configuration written by sta/main.py ("<fn> MY_IOCTL 0_<n>")
  <t>.taint     SUTURE's report (ext_warns.py "all"); every function named in a warning trace
  <t>.vuln      the warnings extracted from it
  <t>.suture.log SUTURE's full log (optional): every taint flow it propagated ("+++TF ... TO: ...")
  <t>.out       the binary, for the static call graph (objdump -d)
Writes, into <result dir>:
  hybrid-taint.txt  one row per function of the program: found by DTA / SUTURE / both / neither
  hybrid-taint.dot  the program's static call graph, nodes coloured by that classification
                    (render with: dot -Tpdf hybrid-taint.dot -o hybrid-taint.pdf)
This reproduces the comparison behind the paper's hybrid taint analysis call graph: functions on
the input-handling path that static analysis alone does not report.
"""
import collections
import os
import re
import subprocess
import sys


def read(path):
    try:
        with open(path, errors="replace") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def main():
    rdir = sys.argv[1]
    t = sys.argv[2] if len(sys.argv) > 2 else os.path.basename(os.path.normpath(rdir))
    p = lambda ext: os.path.join(rdir, t + ext)

    dta_calls = collections.Counter(x.strip() for x in read(p(".analysis")).split(",") if x.strip())
    entries = {}
    for line in read(p(".config")).splitlines():
        parts = line.split()
        if len(parts) >= 2:
            entries[parts[0]] = " ".join(parts[1:])
    taint = read(p(".taint"))
    # Functions in SUTURE's traces: "#####CTX##### a -> b" chains and "fn (file@line)" steps.
    sut = collections.Counter()
    for m in re.finditer(r"^#####CTX##### (.+)$", taint, re.M):
        for fn in m.group(1).split("->"):
            sut[fn.strip()] += 0
    for m in re.finditer(r"^([A-Za-z_][A-Za-z0-9_]*) \([^()]*@\d+\)$", taint, re.M):
        sut[m.group(1)] += 0
    warned = collections.Counter(re.findall(r"fun_name: (\w+)", read(p(".vuln"))))
    # Taint flows SUTURE propagated, attributed to the innermost function of the TO context.
    reached = collections.Counter(
        m.group(1) for m in re.finditer(r"TO: .*?\((?:[A-Za-z_]\w* -> )*?([A-Za-z_]\w*) -> \) tr_len", read(p(".suture.log"))))
    for fn, n in warned.items():
        sut[fn] += n

    # Static call graph of the program's own functions (text symbols with a body).
    out = subprocess.run(["objdump", "-d", "--no-show-raw-insn", p(".out")],
                         capture_output=True, text=True).stdout
    funcs, edges, cur = [], set(), None
    for line in out.splitlines():
        m = re.match(r"^[0-9a-f]+ <([^>@]+)>:$", line)
        if m:
            cur = m.group(1)
            funcs.append(cur)
            continue
        m = re.search(r"\bcall\s+[0-9a-f]+ <([^>+@]+)", line)
        if m and cur:
            edges.add((cur, m.group(1)))
    skip = re.compile(r"^(_|\.|deregister_tm_clones$|register_tm_clones$|frame_dummy$)")
    prog = [f for f in dict.fromkeys(funcs) if not skip.match(f)]
    pset = set(prog)
    edges = sorted((a, b) for a, b in edges if a in pset and b in pset)

    def cat(fn):
        d, s = fn in dta_calls, fn in warned
        return "both" if d and s else "DTA only" if d else "SUTURE only" if s else "neither"

    rows = [(fn, dta_calls.get(fn, 0), entries.get(fn, ""), warned.get(fn, 0), reached.get(fn, 0), cat(fn)) for fn in prog]
    with open(os.path.join(rdir, "hybrid-taint.txt"), "w") as f:
        w = lambda s="": f.write(s + "\n")
        w(f"Hybrid taint report for {t}")
        w(f"  DTA: {len(dta_calls)} functions executed on the input path ({sum(dta_calls.values())} calls)")
        w(f"  SUTURE: {len(entries)} entry functions configured; warnings in {len(warned)} functions "
          f"({sum(warned.values())} warnings); taint propagated into {len(reached)} functions"
          + ("" if reached else " (no <t>.suture.log)"))
        w()
        w("'found by' counts SUTURE as finding a function when SUTURE reports a warning in it (the")
        w("functions named in its report, .taint/.vuln). 'taint flows' counts the flows SUTURE's log")
        w("shows propagating into the function, whether or not a detector warned there.")
        w()
        w(f"{'function':<28}{'DTA calls':>10}  {'SUTURE entry':<16}{'warnings':>9}{'taint flows':>13}  found by")
        for fn, dc, en, wn, tf, c in sorted(rows, key=lambda r: (["both", "DTA only", "SUTURE only", "neither"].index(r[5]), r[0])):
            w(f"{fn:<28}{dc:>10}  {en:<16}{wn:>9}{tf:>13}  {c}")
        w()
        for c in ["both", "DTA only", "SUTURE only"]:
            w(f"{c}: " + ", ".join(sorted(r[0] for r in rows if r[5] == c)))
        w(f"SUTURE taint reached but no warning: " + ", ".join(sorted(r[0] for r in rows if r[4] and not r[3])))
    colour = {"both": "#7fc97f", "DTA only": "#fdc086", "SUTURE only": "#beaed4", "neither": "#ffffff"}
    with open(os.path.join(rdir, "hybrid-taint.dot"), "w") as f:
        f.write(f'digraph "{t}" {{\n  rankdir=LR; node [shape=box, style=filled, fontname=Helvetica];\n')
        f.write('  subgraph cluster_legend { label="found by"; fontname=Helvetica; ' +
                " ".join(f'"{k}" [fillcolor="{v}"];' for k, v in colour.items()) + " }\n")
        for fn, *_, c in rows:
            f.write(f'  "{fn}" [fillcolor="{colour[c]}"];\n')
        for a, b in edges:
            f.write(f'  "{a}" -> "{b}";\n')
        f.write("}\n")
    sys.stdout.write(read(os.path.join(rdir, "hybrid-taint.txt")))


if __name__ == "__main__":
    main()
