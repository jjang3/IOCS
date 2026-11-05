#!/bin/bash
# Build SUTURE and the LLVM/clang 9 it needs (x86-64 Linux; the bundled z3 is x86-64).
#   third_party/build_suture.sh [suture dir (default third_party/SUTURE)] [deps dir (default third_party/.deps)]
# iocs.sh finds the default locations by itself; elsewhere, set SUTURE_HOME and LLVM_ROOT.
# Produces <deps>/llvm/build/bin/{clang,opt,...}, <suture>/env.sh and
# <suture>/llvm_analysis/MainAnalysisPasses/build_dir/SoundyAliasAnalysis/libSoundyAliasAnalysis.so.
# This is SUTURE's own setup_suture.py + llvm_analysis/build.sh with three differences: LLVM is
# fetched at pinned SHAs (versions.env), built Release with assertions (setup_suture.py's bare
# "cmake .." is a Debug build, which also has assertions), and X86-only without runtimes.
# SUTURE's EntryPointIdentifier helper fails to link without LLVM's test libraries; IOCS does not
# use it (src/sta writes SUTURE's entry config).
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd); . "$here/versions.env"
src=$(cd "${1:-$here/SUTURE}" && pwd); deps=${2:-$here/.deps}; mkdir -p "$deps"; deps=$(cd "$deps" && pwd)
jobs=${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu)}
fetch() {  # <dir> <url> <sha>
    if [ "$(git -C "$1" rev-parse HEAD 2>/dev/null)" != "$3" ]; then
        mkdir -p "$1" && git -C "$1" init -q && { git -C "$1" remote add origin "$2" 2>/dev/null || true; }
        git -C "$1" fetch -q --depth 1 origin "$3" && git -C "$1" checkout -q FETCH_HEAD
    fi
}
L=$deps/llvm
fetch "$L" https://github.com/llvm-mirror/llvm "$LLVM_MIRROR_LLVM_SHA"
fetch "$L/tools/clang" https://github.com/llvm-mirror/clang "$LLVM_MIRROR_CLANG_SHA"
if [ ! -x "$L/build/bin/opt" ]; then
    cmake -S "$L" -B "$L/build" -G Ninja -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_ASSERTIONS=ON \
        -DLLVM_TARGETS_TO_BUILD=X86 -DLLVM_INCLUDE_TESTS=OFF -DLLVM_INCLUDE_EXAMPLES=OFF \
        -DLLVM_INCLUDE_BENCHMARKS=OFF -DCLANG_INCLUDE_TESTS=OFF
    ninja -C "$L/build" -j "$jobs"
fi
printf 'export LLVM_ROOT=%s\nexport PATH=$LLVM_ROOT/bin:$PATH\n' "$L/build" > "$src/env.sh"
( . "$src/env.sh" && cd "$src/llvm_analysis" && ./build.sh )
test -f "$src/llvm_analysis/MainAnalysisPasses/build_dir/SoundyAliasAnalysis/libSoundyAliasAnalysis.so"
echo "SUTURE built: $src (LLVM 9 at $L/build)"
