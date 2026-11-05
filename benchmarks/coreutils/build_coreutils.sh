#!/bin/bash
# Build GNU coreutils 8.31 for IOCS (paper Table 1).
# Run in the iocs-nginx-build:20.04 image (gcc 9.4, glibc 2.31) with the repo at /iocs:
#   docker run --rm --platform linux/amd64 -v "$PWD":/iocs iocs-nginx-build:20.04 bash benchmarks/coreutils/build_coreutils.sh
#
# Produces $COREUTILS_HOME (default build/coreutils/coreutils-8.31) built with
# -O0 -gdwarf-2 -save-temps=obj, so every object has its assembly next to it (src/<u>.s), plus
# an Intel-syntax copy src/<u>.intel for the rewriter's input verifier, and a pristine copy of
# every AT&T .s as <file>.s.orig. INTEL=0 skips the Intel pass.
set -euo pipefail
IOCS_HOME=${IOCS_HOME:-/iocs}
. "$IOCS_HOME/third_party/versions.env"   # COREUTILS_VERSION, COREUTILS_SHA256
V=$COREUTILS_VERSION
COREUTILS_HOME=${COREUTILS_HOME:-$IOCS_HOME/build/coreutils/coreutils-$V}
TARBALL=$(dirname "$COREUTILS_HOME")/coreutils-$V.tar.xz
CFLAGS_IOCS="-O0 -gdwarf-2 -save-temps=obj"
jobs=$(nproc 2>/dev/null || echo 4)

mkdir -p "$(dirname "$COREUTILS_HOME")"
if [ ! -f "$COREUTILS_HOME/Makefile" ] || [ "${REBUILD:-0}" = 1 ]; then
    [ -f "$TARBALL" ] || curl -fsSL -o "$TARBALL" "https://ftp.gnu.org/gnu/coreutils/coreutils-$V.tar.xz"
    echo "$COREUTILS_SHA256  $TARBALL" | sha256sum -c -
    rm -rf "$COREUTILS_HOME" && tar -xJf "$TARBALL" -C "$(dirname "$COREUTILS_HOME")"
    cd "$COREUTILS_HOME"
    # configure once; FORCE_UNSAFE_CONFIGURE lets it run as root inside the container.
    # --without-gmp keeps factor's code path the same on every host; --disable-nls drops gettext.
    FORCE_UNSAFE_CONFIGURE=1 ./configure --prefix="$COREUTILS_HOME/install" --disable-nls --without-gmp \
        --without-selinux CFLAGS="$CFLAGS_IOCS" > configure.iocs.log 2>&1
fi
cd "$COREUTILS_HOME"

if [ "${INTEL:-1}" = 1 ]; then
    # Intel-syntax pass: the same build with -masm=intel, kept only as src/*.intel for the
    # rewriter's input verifier. make -k: gnulib's lib/mktime.c defines a function named shr,
    # which the Intel-syntax assembler rejects as an operator; lib/ objects are not needed here.
    make -k -j"$jobs" CFLAGS="$CFLAGS_IOCS -masm=intel" > make.intel.log 2>&1 || true
    find src lib -name '*.s' -exec sh -c 'mv "$0" "${0%.s}.intel"' {} \;
    find src lib -name '*.o' -delete; find src lib -name '*.i' -delete
    rm -f src/*.a lib/*.a
    for u in basename pwd wc cp factor ls; do [ -f "src/$u.intel" ] || { echo "Intel pass produced no src/$u.intel"; exit 1; }; done
fi
make -j"$jobs" > make.log 2>&1
find src lib -name '*.s' -exec sh -c 'cp "$0" "$0.orig"' {} \;
echo "coreutils $V built: $(find src -maxdepth 1 -name '*.s' | wc -l) src .s files, $(ls src | grep -cE '^[a-z]+$') programs"
./src/basename --version | head -1
