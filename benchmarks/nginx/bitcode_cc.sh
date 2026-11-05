#!/bin/bash
# bitcode_cc.sh: the CC that "nginx.sh nginx bitcode" gives Nginx's own objs/Makefile, so each
# object is compiled with its configure-time include paths and defines. It compiles to LLVM
# bitcode with SUTURE's clang 9 instead: "-o objs/X.o" becomes "-o $BC_DIR/objs/X.bc"; gcc-only
# flags are dropped. The tree's objects are not touched.
C=${SUTURE_CLANG:-${LLVM_ROOT:-/opt/suture_deps/llvm/build}/bin/clang}
args=() out=
while [ $# -gt 0 ]; do
    case $1 in
        -o) out=$2; shift ;;
        -save-temps*|-gno-variable-location-views|-gdwarf-*|-O*|-W*|-pipe) ;;
        *) args+=("$1") ;;
    esac
    shift
done
[ -n "$out" ] || { echo "bitcode_cc.sh: no -o" >&2; exit 1; }
bc=$BC_DIR/${out%.o}.bc
mkdir -p "$(dirname "$bc")"
# glibc >= 2.32 has no <sys/sysctl.h>, which Nginx's Linux config includes (configured on 2.31)
# but does not use there: an empty one stands in.
shim=()
if [ ! -f /usr/include/sys/sysctl.h ] && [ ! -f /usr/include/x86_64-linux-gnu/sys/sysctl.h ]; then
    mkdir -p "$BC_DIR/.shim/sys" && : > "$BC_DIR/.shim/sys/sysctl.h"; shim=(-idirafter "$BC_DIR/.shim")
fi
# -g, no -O: what iocs.sh bitcode gives SUTURE for tiny and coreutils.
exec "$C" -emit-llvm -g -w "${shim[@]}" "${args[@]}" -o "$bc"
