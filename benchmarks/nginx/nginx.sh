#!/bin/bash
# Nginx steps: nginx.sh nginx <step> [<step> ...] (NGINX_HOME: the built tree, build_nginx.sh)
#   patch     rewrite objs/src/**/*.s in place from the .s.bak copies, then lib/table.so
#             (IOCS_REWRITE_MODE=tree: src/ptr_offset_tree with $NGINX_RESULT's SUTURE results)
#   bitcode   one LLVM bitcode module for SUTURE: every object of objs/Makefile compiled with its
#             own flags by SUTURE's clang 9 (bitcode_cc.sh), linked by llvm-link (iocs:dev)
#   bclink    only the llvm-link of bitcode (an image whose LLVM 9 has llvm-link: iocs-suture:llvm9)
#   sta       SUTURE on nginx.bc with the entry config of every DTA function (nginx.analysis)
#             and all of its parameters (iocs.sh sta, IOCS_STA_CONFIG=dta; dta-roots: only the
#             DTA functions that no other DTA function calls) (iocs:dev)
#   sta_split the same entry config, SUTURE once per entry function, each with a timeout
#             (suture_split.sh; SUTURE_ENTRY_TIMEOUT, SUTURE_JOBS) (iocs:dev)
# NGINX_RESULT (default ${IOCS_RESULT_DIR:-result}/nginx) holds nginx.out, nginx.analysis,
# nginx.bc/.ll, nginx.config/.taint/.vuln and, in tree mode, trees.txt.
# nginx.out is always the pristine build (NGINX_ORIG, default <NGINX_HOME>/../nginx.orig, which
# run_nginx.sh copies right after build_nginx.sh): after a relink objs/nginx is a rewritten binary.

PS3="Select options: "
# Paths come from config.env (see config.env.example);
# repo paths are derived from this script's location, not from the caller's cwd.
IOCS_HOME=$( cd "$(dirname "${BASH_SOURCE[0]}")/../.." ; pwd -P )
[ -f "$IOCS_HOME/config.env" ] && . "$IOCS_HOME/config.env"
input=$1

options=("Patch" "Compile")

# This is coreutils path
NGINX_HOME=${NGINX_HOME:-/opt/nginx-1.3.9}
nginx_path="$NGINX_HOME/objs/src"
nginx_home_path="$NGINX_HOME/"
nginx_install_path="$NGINX_HOME/debug_x86_64/sbin"

# This is used to setup test path
current_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
input_path=${IOCS_HOME}/benchmarks
test_path=${IOCS_HOME}/result
result_path=${test_path}/$1
NGINX_RESULT=${NGINX_RESULT:-${IOCS_RESULT_DIR:-$test_path}/nginx}
LLVM_ROOT=${LLVM_ROOT:-/opt/suture_deps/llvm/build}
NGINX_ORIG=${NGINX_ORIG:-$(dirname "$NGINX_HOME")/nginx.orig}

# The analysis input: the pristine binary, never objs/nginx (rewritten after any relink).
pristine_out()
{
    [ -s "$NGINX_ORIG" ] || { echo "nginx.sh: no pristine binary $NGINX_ORIG (build_nginx.sh, then cp objs/nginx)" >&2; return 1; }
    if command -v objdump > /dev/null && objdump -d "$NGINX_ORIG" | grep -q rdgsbase; then
        echo "nginx.sh: $NGINX_ORIG is a rewritten binary (rdgsbase); rebuild with build_nginx.sh" >&2; return 1
    fi
    mkdir -p "$NGINX_RESULT" && cp "$NGINX_ORIG" "$NGINX_RESULT/nginx.out"
}

patch()
{
    # Copy original backup files every time before rewriting
    find "$nginx_path" -type f -name "*.s.bak" -exec bash -c 'file_path="$1"; 
    dir_path=$(dirname "$file_path"); 
    file_name=$(basename "$file_path" .s.bak); 
    new_file_path="$dir_path/${file_name}.s";
    object_file_path="$dir_path/${file_name}.o"; 
    cp "$file_path" "$new_file_path";
    as "$new_file_path" -o "$object_file_path"' _ {} \;
    echo "Patch"
    #python3 binary_patch_old.py --fun fun.list --dir ${nginx_path}
    #python3 binary_patch.py --fun fun.list --dir ${nginx_path}
    # main.py --directory reads <dir>/nginx.analysis (named after --binary's stem); the
    # committed DTA function list is benchmarks/nginx/nginx.analysis (whitespace after commas removed).
    [ -f "${nginx_path}/nginx.analysis" ] || tr -d ' \n' < "$current_path/nginx.analysis" > "${nginx_path}/nginx.analysis"
    if [ "${IOCS_REWRITE_MODE:-directory}" = tree ]; then
        # Tree mode: SUTURE's tainted variables (sta) and the pointer offset trees, computed on the
        # linked program; every object's .s is rewritten. Its result files are in $NGINX_RESULT.
        [ -s "$NGINX_RESULT/nginx.taint" ] || { echo "nginx.sh: no $NGINX_RESULT/nginx.taint (run: nginx.sh nginx sta)" >&2; return 1; }
        pristine_out || return 1
        ( cd "$IOCS_HOME/src/ptr_offset_tree/asm_rewriter" && python3 main.py --binary "$NGINX_RESULT/nginx.out" \
            --directory "${nginx_path}" --result "$NGINX_RESULT"; exit $? ) || return 1
        cp "$NGINX_RESULT/table.c" "${nginx_path}/table.c"     # (make lib builds it next to the objects)
    else
        # main.py must run from the rewriter directory (it finds src/ via the cwd).
        ( cd "$IOCS_HOME/src/rewriter" && python3 main.py --binary nginx.out --directory ${nginx_path}; exit $? ) || return 1
    fi
    cp ${input_path}/libMakefile ${nginx_path}/Makefile
    cd ${nginx_path}
    make lib
}

bitcode()
{
    local C=${SUTURE_CLANG:-$LLVM_ROOT/bin/clang}
    [ -x "$C" ] || { echo "nginx.sh: SUTURE clang not found: $C" >&2; return 1; }
    mkdir -p "$NGINX_RESULT"
    rm -rf "$NGINX_RESULT/bc"
    # Every object of objs/nginx, built by Nginx's own rules (-B: all of them; the CC writes only
    # under bc/, so the tree's objects stay as they are).
    local objs; objs=$(cd "$NGINX_HOME" && grep -oE '^objs/[^:]+\.o' objs/Makefile)
    ( cd "$NGINX_HOME" && BC_DIR="$NGINX_RESULT/bc" SUTURE_CLANG="$C" make -s -B -f objs/Makefile \
        CC="bash $current_path/bitcode_cc.sh" $objs ) > "$NGINX_RESULT/bitcode.log" 2>&1 \
        || { tail -20 "$NGINX_RESULT/bitcode.log" >&2; return 1; }
    echo "nginx.sh: $(find "$NGINX_RESULT/bc" -name '*.bc' | wc -l) bitcode files ($(echo $objs | wc -w) objects)"
    if [ -x "${LLVM_LINK:-$LLVM_ROOT/bin/llvm-link}" ]; then bclink; else
        echo "nginx.sh: no llvm-link in $LLVM_ROOT/bin; run 'nginx.sh nginx bclink' in iocs-suture:llvm9"; fi
}

bclink()
{
    local L=${LLVM_LINK:-$LLVM_ROOT/bin/llvm-link}
    ( cd "$NGINX_RESULT/bc" && "$L" $(find . -name '*.bc' | sort) -o ../nginx.bc ) || return 1
    "$LLVM_ROOT/bin/llvm-dis" "$NGINX_RESULT/nginx.bc" -o "$NGINX_RESULT/nginx.ll" || return 1
    echo "nginx.sh: $NGINX_RESULT/nginx.bc ($(wc -c < "$NGINX_RESULT/nginx.bc" | tr -d ' ') bytes)"
}

sta()
{
    [ -s "$NGINX_RESULT/nginx.bc" ] || { echo "nginx.sh: no $NGINX_RESULT/nginx.bc (run: nginx.sh nginx bitcode)" >&2; return 1; }
    pristine_out || return 1
    tr -d ' \n' < "$current_path/nginx.analysis" > "$NGINX_RESULT/nginx.analysis"
    ( cd "$IOCS_HOME" && IOCS_RESULT_DIR=$(dirname "$NGINX_RESULT") IOCS_STA_CONFIG=${IOCS_STA_CONFIG:-dta} ./iocs.sh nginx sta )
}

sta_split()
{
    # The same entry config as sta, SUTURE run per entry function with a timeout each
    # (suture_split.sh: one run of all 79 entries takes days); writes nginx.taint/.vuln.
    [ -s "$NGINX_RESULT/nginx.bc" ] || { echo "nginx.sh: no $NGINX_RESULT/nginx.bc (run: nginx.sh nginx bitcode)" >&2; return 1; }
    pristine_out || return 1
    tr -d ' \n' < "$current_path/nginx.analysis" > "$NGINX_RESULT/nginx.analysis"
    local roots=(); [ "${IOCS_STA_CONFIG:-dta}" = dta-roots ] && roots=(--roots "$NGINX_RESULT/nginx.ll")
    ( cd "$IOCS_HOME/src/ptr_offset_tree/asm_rewriter" && python3 ../sta/main.py --binary "$NGINX_RESULT/nginx.out" \
        --analysis "$NGINX_RESULT/nginx.analysis" --config "$NGINX_RESULT/nginx.config" ${roots[@]+"${roots[@]}"} ) || return 1
    bash "$current_path/suture_split.sh" "$NGINX_RESULT" || return 1
    [ -s "$NGINX_RESULT/nginx.taint" ]
}

compile()
{
    echo "Compile nginx app" 
    cd ${nginx_home_path}
    make && make install
    cp ${nginx_install_path}/nginx ${result_path}/nginx
}

# Non-interactive use: <script> <target> <step> [<step> ...]
if [ $# -gt 1 ]; then
    shift
    for s in "$@"; do "$s" || exit 1; done
    exit 0
fi

while true; do
    select option in "${options[@]}" Quit
    do
        case $REPLY in
            # 1) echo "Selected $option"; migrate; break;;
            1) echo "Selected $option"; patch; break;;
            2) echo "Selected $option"; compile; break;;
            $((${#options[@]}+1))) echo "Finished!"; break 2;;
            *) echo "Wrong input"; break;
        esac;
    done
done


