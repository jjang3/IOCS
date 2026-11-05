#!/bin/bash
# Build Nginx 1.3.9 for IOCS (Chapter 14 / paper Nginx evaluation).
# Run in the iocs-nginx-build:20.04 image (docker/nginx-build.Dockerfile) with the repo at /iocs:
#   docker run --rm --platform linux/amd64 -v "$PWD":/iocs iocs-nginx-build:20.04 bash benchmarks/nginx/build_nginx.sh
#
# Produces $NGINX_HOME (default build/nginx/nginx-1.3.9) with objs/src/**/{*.s,*.o} from
# -save-temps=obj, installs to $NGINX_PREFIX, and keeps a pristine copy of every AT&T .s as
# <file>.s.orig so a rewrite can always start from the compiler's output.
#
# Recipe = nginx_compile.sh with three corrections:
#  - no -masm=intel here: the rewriter needs AT&T .s; INTEL=1 adds a second pass that writes
#    the Intel-syntax .intel files the PRE verifier reads (what nginx_compile.sh produced);
#  - only the -Werror token is removed: nginx_compile.sh's "sed '/-Werror/d'" deletes the whole
#    CFLAGS line, including -g -gdwarf-2 -save-temps=obj;
#  - patches/nginx-1.3.9-crypt_r.patch, needed with libxcrypt (Ubuntu >= 20.04).
set -euo pipefail
IOCS_HOME=${IOCS_HOME:-/iocs}
. "$IOCS_HOME/third_party/versions.env"   # NGINX_VERSION, NGINX_SHA256
NGINX_HOME=${NGINX_HOME:-$IOCS_HOME/build/nginx/nginx-$NGINX_VERSION}
NGINX_PREFIX=${NGINX_PREFIX:-$(dirname "$NGINX_HOME")/install}
TARBALL=$(dirname "$NGINX_HOME")/nginx-$NGINX_VERSION.tar.gz
SHA=$NGINX_SHA256
CC_OPT="-O0 -W -Wpointer-arith -Wno-unused -g -gdwarf-2 -save-temps=obj -gno-variable-location-views"

mkdir -p "$(dirname "$NGINX_HOME")"
[ -f "$TARBALL" ] || curl -fsSL -o "$TARBALL" "https://nginx.org/download/nginx-$NGINX_VERSION.tar.gz"
echo "$SHA  $TARBALL" | sha256sum -c -
rm -rf "$NGINX_HOME" && tar -xzf "$TARBALL" -C "$(dirname "$NGINX_HOME")"
[ -d "$NGINX_HOME" ] || { echo "tarball did not unpack to $NGINX_HOME"; exit 1; }
cd "$NGINX_HOME"
for p in "$IOCS_HOME"/benchmarks/nginx/patches/nginx-$NGINX_VERSION-*.patch; do patch -p1 < "$p"; done

./configure --prefix="$NGINX_PREFIX" --with-cc-opt="$CC_OPT" > objs.configure.log 2>&1
# Write through a temp file: sed -i cannot rename into some bind mounts (colima virtiofs).
sed 's/ -Werror//' objs/Makefile > /tmp/objs.Makefile && cat /tmp/objs.Makefile > objs/Makefile

if [ "${INTEL:-0}" = 1 ]; then
    # Intel-syntax pass for the PRE verifier: compile with -masm=intel, keep the .s as .intel.
    sed "s/-gno-variable-location-views/-gno-variable-location-views -masm=intel/" objs/Makefile > /tmp/mk.intel
    make -f /tmp/mk.intel -j"$(nproc)" > make.intel.log 2>&1
    find objs/src -name '*.s' -exec sh -c 'mv "$0" "${0%.s}.intel"' {} \;
    find objs/src -name '*.o' -delete
fi

make -j"$(nproc)" > make.log 2>&1
make install > make.install.log 2>&1
find objs/src -name '*.s' -exec sh -c 'cp "$0" "$0.orig"' {} \;
echo "nginx built: $(find objs/src -name '*.s' | wc -l) .s, $(find objs/src -name '*.o' | wc -l) .o, $(find objs/src -name '*.intel' | wc -l) .intel"
"$NGINX_PREFIX/sbin/nginx" -V 2>&1 | head -1
