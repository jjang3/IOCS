#!/bin/bash
# IOCS pipeline driver for one input program, benchmarks/<target>.c.
#
#   ./iocs.sh <target> <stage> [<stage> ...]     run stages in order
#   ./iocs.sh <target>                           interactive menu
#
# Stages:
#   tools    build the PIN/libdft64 dynamic taint tool (src/dta)
#   build    compile benchmarks/<t>.c into result/<t>/ (-O0 -gdwarf-2 -save-temps=obj)
#   bitcode  LLVM 9 bitcode for SUTURE
#   dta      dynamic taint analysis under PIN -> <t>.analysis (needs ptrace)
#   sta      SUTURE entry config (src/sta; IOCS_STA_CONFIG=dta: every function of <t>.analysis,
#            dta-roots: those of them that no other one calls)
#            + SUTURE -> <t>.config, <t>.taint, <t>.vuln, <t>.suture.log, and the hybrid DTA/STA
#            report hybrid-taint.{txt,dot}
#   rewrite  compartment table (table.c) + rewritten <t>.s (src/rewriter; IOCS_REWRITE_MODE=tree:
#            src/ptr_offset_tree, SUTURE-filtered variables + pointer offset trees)
#   link     lib/table.so + <t>.new
#   run      LD_PRELOAD=./lib/table.so ./<t>.new (needs a CPU/kernel with FSGSBASE)
#   all      build dta sta rewrite link
#
# scripts/run.sh runs these in the right environment and records the evidence.
# Tool locations default to the iocs:dev image (/opt) or third_party/ (see config.env.example).
set -u
PS3="Select options: "

IOCS_HOME=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
[ -f "$IOCS_HOME/config.env" ] && . "$IOCS_HOME/config.env"

# Defaults: the tools inside the iocs:dev image (/opt), else the copies built from third_party/
# on this host (third_party/get_pin.sh, third_party/build_suture.sh).
first() { for d in "$@"; do [ -e "$d" ] && { echo "$d"; return; }; done; echo "$1"; }
SUTURE_HOME=${SUTURE_HOME:-$(first /opt/suture/run_nohup.sh "$IOCS_HOME/third_party/SUTURE/run_nohup.sh")}
SUTURE_HOME=${SUTURE_HOME%/run_nohup.sh}
LLVM_ROOT=${LLVM_ROOT:-$(first /opt/suture_deps/llvm/build "$IOCS_HOME/third_party/.deps/llvm/build")}
SUTURE_CLANG=${SUTURE_CLANG:-$LLVM_ROOT/bin/clang}
PIN_ROOT=${PIN_ROOT:-$(first /opt/pin-3.27 "$IOCS_HOME/third_party/pin/pin-3.27")}
LIBDFT64=${LIBDFT64:-$IOCS_HOME/third_party/libdft64}
case $LIBDFT64 in /*) ;; *) LIBDFT64=$IOCS_HOME/$LIBDFT64 ;; esac
export LLVM_ROOT LIBDFT64   # LIBDFT64 is read by src/dta/sources/makefile.rules
SUTURE_TIMEOUT=${SUTURE_TIMEOUT:-3600}
export PIN_ROOT

CFLAGS="-O0 -gdwarf-2"

taint_path=$IOCS_HOME/src/dta
sta_path=$IOCS_HOME/src/sta
rewrite_path=$IOCS_HOME/src/rewriter
arcs_input_path=$IOCS_HOME/benchmarks
arcs_result_path=${IOCS_RESULT_DIR:-$IOCS_HOME/result}   # (IOCS_RESULT_DIR: e.g. a sweep's own result tree)

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
[ $# -ge 1 ] || usage
input=$1; shift

arcs_i_result_path=${arcs_result_path}/${input}
arcs_ll_file=${arcs_i_result_path}/${input}.ll
arcs_bc_file=${arcs_i_result_path}/${input}.bc
arcs_bin_file=${arcs_i_result_path}/${input}.out
arcs_config_file=${arcs_i_result_path}/${input}.config
arcs_analysis_file=${arcs_i_result_path}/${input}.analysis
arcs_vuln_file=${arcs_i_result_path}/${input}.vuln
arcs_taint_file=${arcs_i_result_path}/${input}.taint

die() { echo "iocs.sh: $*" >&2; exit 1; }
need() { [ -s "$1" ] || die "missing or empty: $1${2:+ ($2)}"; }

tools()
{
    echo "Build the DTA tool"
    [ -x "$PIN_ROOT/pin" ] || die "PIN not found at PIN_ROOT=$PIN_ROOT (run third_party/get_pin.sh)"
    [ -f "$LIBDFT64/Makefile" ] || die "libdft64 missing: git submodule update --init third_party/libdft64"
    ( cd "$LIBDFT64" && make ) || die "libdft64 build failed"
    ( cd "$taint_path/sources" && bash compile.sh ) || die "pintool build failed"
    need "$taint_path/lib/libdft-mod.so"
}

build()
{
    echo "Build ${input}"
    mkdir -p "$arcs_result_path"                 # benchmarks/Makefile expects result/ to exist
    ( cd "$arcs_input_path" && make "${input}.out" ) || die "make ${input}.out failed"
    need "$arcs_i_result_path/${input}.s"
}

bitcode()
{
    # SUTURE's clang 9: -g, no -O (see scripts/sta_variants.sh for other bitcode recipes).
    [ -x "$SUTURE_CLANG" ] || die "SUTURE clang not found: $SUTURE_CLANG"
    mkdir -p "$arcs_i_result_path"
    if [ ! -f "$arcs_ll_file" ]; then
        echo "LLVM IR (.ll) file doesn't exist"
        "$SUTURE_CLANG" -emit-llvm -S -g -c -o "${arcs_ll_file}" "${arcs_input_path}/${input}.c" || die "clang .ll failed"
    fi
    if [ ! -f "$arcs_bc_file" ]; then
        echo "LLVM IR (.bc) file doesn't exist"
        "$SUTURE_CLANG" -emit-llvm -g -c -o "${arcs_bc_file}" "${arcs_input_path}/${input}.c" || die "clang .bc failed"
    fi
}

dta()
{
    echo "Dynamic taint analysis"
    need "$arcs_bin_file" "run: ./iocs.sh $input build"
    need "$taint_path/lib/libdft-mod.so" "run: ./iocs.sh $input tools"
    # Workload definitions live next to the program (benchmarks/, or IOCS_TARGET_DIR):
    #   <t>.dta.args  sourced bash: sets DTA_ARGS=(...) (and may create files under $work,
    #                 set DTA_STDIN, and define dta_verify); PIN runs the program once with them
    #   <t>.dta.sh    a server: PIN starts the program in the background, the hook drives it
    #                 (IOCS_DTA_PID is PIN's pid), then PIN is stopped with SIGINT
    #   <t>.dta.in    stdin for a plain foreground run
    local tdir=${IOCS_TARGET_DIR:-$arcs_input_path}
    local exercise="$tdir/${input}.dta.sh" argsfile="$tdir/${input}.dta.args"
    local work="$arcs_i_result_path/dta"
    rm -rf "$work" && mkdir -p "$work"
    : > "$work/dwarf.out"                          # debug input of the pintool (IOCS_DWARF_OUT)
    if [ -f "$argsfile" ]; then
        local DTA_ARGS=() DTA_STDIN=/dev/null
        # shellcheck disable=SC1090
        . "$argsfile"
        printf '%s\n' "${DTA_ARGS[@]+"${DTA_ARGS[@]}"}" > "$work/args.txt"
        ( cd "$work" && IOCS_DWARF_OUT="$work/dwarf.out" \
            "$PIN_ROOT/pin" -follow-execv -t "$taint_path/lib/libdft-mod.so" -- "${arcs_bin_file}" \
            ${DTA_ARGS[@]+"${DTA_ARGS[@]}"} < "$DTA_STDIN" > "$work/stdout" 2> "$work/stderr" ) \
            || echo "iocs.sh: warning: program exited with status $? under PIN" >&2
    elif [ -f "$exercise" ]; then
        ( cd "$work" && IOCS_DWARF_OUT="$work/dwarf.out" exec setsid \
            "$PIN_ROOT/pin" -follow-execv -t "$taint_path/lib/libdft-mod.so" -- "${arcs_bin_file}" \
            > "$work/stdout" 2> "$work/stderr" ) &
        local pid=$!
        IOCS_DTA_PID=$pid bash "$exercise" "$arcs_bin_file" || echo "iocs.sh: warning: $exercise returned $?" >&2
        kill -INT -- "-$pid" 2>/dev/null || kill -INT "$pid" 2>/dev/null
        wait "$pid"
    else
        local in=/dev/stdin; [ -f "$tdir/${input}.dta.in" ] && in="$tdir/${input}.dta.in"
        ( cd "$work" && IOCS_DWARF_OUT="$work/dwarf.out" \
            "$PIN_ROOT/pin" -follow-execv -t "$taint_path/lib/libdft-mod.so" -- "${arcs_bin_file}" < "$in" )
    fi
    # PIN prints its own errors (e.g. ptrace_scope) to stdout; surface them on failure.
    grep -h '^E:' "$work/stdout" "$work/stderr" 2>/dev/null | sed 's/^/  pin: /' >&2
    # The pintool never flushes or closes dft.out; record an empty trace as a failure.
    need "$work/dft.out" "the pintool wrote no trace"
    mv "$work/dft.out" "${arcs_analysis_file}"
}

sta()
{
    echo "Find vulnerable data"
    need "$arcs_bin_file" "run: ./iocs.sh $input build"
    if [ "${IOCS_STA_CONFIG:-}" = dta ] || [ "${IOCS_STA_CONFIG:-}" = dta-roots ]; then
        # Entry config from the DTA trace: every function of <t>.analysis, all of its parameters
        # user-controlled (for a program whose input does not come from argv, e.g. Nginx);
        # dta-roots: only those no other traced function calls (call graph of <t>.ll).
        need "$arcs_analysis_file" "run: ./iocs.sh $input dta"
        local roots=(); [ "${IOCS_STA_CONFIG}" = dta-roots ] && { need "$arcs_ll_file" "run: ./iocs.sh $input bitcode"; roots=(--roots "$arcs_ll_file"); }
        ( cd "$IOCS_HOME/src/ptr_offset_tree/asm_rewriter" && python3 ../sta/main.py --binary "${arcs_bin_file}" \
            --analysis "$arcs_analysis_file" --config "$arcs_config_file" ${roots[@]+"${roots[@]}"} ) || die "STA config generation failed"
    else
        # src/sta/taint_analysis.py imports dwarf_analysis_old from the rewriter's src/.
        PYTHONPATH="$rewrite_path/src${PYTHONPATH:+:$PYTHONPATH}" python3 "$sta_path/main.py" --binary "${arcs_bin_file}" \
            || die "STA config generation failed"
    fi
    need "$arcs_config_file" "STA wrote no SUTURE entry config"
    cat "$arcs_config_file"
    bitcode
    cp "${arcs_bc_file}" "$arcs_config_file" "$SUTURE_HOME/benchmark" || die "cannot copy into $SUTURE_HOME/benchmark"
    local bc_name config_name current_date config_folder
    bc_name=$(basename "${arcs_bc_file}")
    config_name=$(basename "${bc_name}" .bc)
    current_date=$(date "+%Y-%m-%d")
    config_folder="warns-$config_name.config-$current_date"
    # Run in a subshell so the cd and env.sh do not leak; poll the log for SUTURE's
    # completion marker.
    (
        cd "$SUTURE_HOME" || exit 1
        [ -f env.sh ] && . ./env.sh
        if [ -d "./benchmark/$config_folder" ]; then
            echo "Delete the existing folder"
            rm -rf "./benchmark/$config_folder"
        fi
        rm -f "./benchmark/$config_name.config.log"
        ./run_nohup.sh "./benchmark/$bc_name" "./benchmark/$config_name.config"
        timeout "$SUTURE_TIMEOUT" bash -c \
            "until grep -q 'Bug Detection Phase finished' ./benchmark/$config_name.config.log 2>/dev/null; do sleep 2; done" \
            || { echo "iocs.sh: SUTURE did not finish within ${SUTURE_TIMEOUT}s" >&2; exit 1; }
        ./ext_warns.sh "./benchmark/$config_name.config.log"
    ) || die "SUTURE failed"

    # ext_warns.sh names the folder with its own date when it runs, which can differ from
    # current_date after a long SUTURE run; use the newest folder it actually created.
    config_folder=$(cd "$SUTURE_HOME/benchmark" && ls -1dt "warns-$config_name.config-"* 2>/dev/null | head -1)
    [ -n "$config_folder" ] || die "ext_warns.sh created no warns-$config_name.config-* folder"
    # Use grep to extract matching lines and awk to parse and format the output correctly
    local input_file="$SUTURE_HOME/benchmark/$config_folder/all"
    cp "$input_file" "$arcs_taint_file" || die "no SUTURE report at $input_file"
    # Keep SUTURE's full log too (every taint flow it propagated), for the hybrid report.
    cp "$SUTURE_HOME/benchmark/$config_name.config.log" "$arcs_i_result_path/${input}.suture.log"
    if [ -f "$arcs_vuln_file" ]; then
        echo "Delete the existing vuln file"
        rm "$arcs_vuln_file"
    fi
    # gawk named explicitly; the three-argument match() below is a gawk extension.
    grep -oP "([^ ]+) says: ([^@]+)@([0-9]+) \(([^:]+) :(.+)" "$arcs_taint_file" |
    gawk -F' : ' '{
        # Use regex matching to extract vuln_type, file, line_num, fun_name, and the instruction
        match($0, /([^ ]+) says: ([^@]+)@([0-9]+) \(([^:]+) :(.+)/, matches);
        vuln_type = matches[1];
        file = matches[2];
        line_num = matches[3];
        fun_name = matches[4];
        instruction = matches[5];

        # Remove the trailing parenthesis from the instruction
        gsub(/\)$/, "", instruction);

        # Print the captured information including the instruction without the trailing parenthesis
        print "file: " file " - line_num: " line_num " - fun_name: " fun_name "\n\t\t\t- vuln_type: " vuln_type "\n\t\t\t- instruction: " instruction "\n";
    }' > "$arcs_vuln_file"
    # Which functions DTA and SUTURE each found (src/sta/hybrid_report.py).
    [ -s "$arcs_analysis_file" ] && python3 "$sta_path/hybrid_report.py" "$arcs_i_result_path" "$input" > /dev/null
    true
}

rewrite()
{
    echo "Assembly rewriting the application"
    need "$arcs_analysis_file" "run: ./iocs.sh $input dta"
    # The PRE verifier reads each object's .intel (a program's objects need not be named after it:
    # coreutils' base64 is src_base64-basenc.o).
    ls "$arcs_i_result_path"/*.intel > /dev/null 2>&1 || die "no .intel file in $arcs_i_result_path (run: ./iocs.sh $input build; the PRE verifier reads it)"
    # --directory mode (default; the path used for tiny and Nginx): it takes every variable of the
    # functions in <t>.analysis (the DTA trace) and rewrites each .s in the directory.
    # IOCS_REWRITE_MODE=binary selects its --binary path instead, which needs SUTURE's
    # <t>.taint/<t>.vuln and keeps only the tainted variables (0 compartments on tiny, because all
    # of tiny's tainted variables are formal parameters, which this version does not handle).
    # IOCS_REWRITE_MODE=tree runs src/ptr_offset_tree instead: SUTURE's tainted variables plus the
    # pointer offset trees, which lift a tainted callee pointer parameter to the caller objects it
    # can point to over every call (tiny: url_decode's dest into process's request struct); it
    # writes trees.txt, lifted.txt and compartments.txt next to table.c.
    # Paths chosen so result_dir resolves to <repo>/result/<t>; cwd must be the rewriter
    # dir (main.py finds src/ via cwd). "exit $?" keeps this subshell as python's parent:
    # rewriter.py SIGTERMs its parent on failure and must not hit this driver.
    local mode=${IOCS_REWRITE_MODE:-directory}
    if [ "$mode" = binary ] || [ "$mode" = tree ]; then
        # main.py derives result_dir as <grandparent of --binary>/result/<stem> and uses only the stem
        # and that grandparent, so pass result/<t>.out (grandparent = the repo root).
        local rw=$rewrite_path; [ "$mode" = tree ] && rw=$IOCS_HOME/src/ptr_offset_tree/asm_rewriter
        # tree mode tolerates an empty .vuln (a program with no SUTURE warnings, e.g. pwd): it then
        # protects only what the pointer offset trees lift. binary mode still needs tainted variables.
        [ "$mode" = tree ] || need "$arcs_vuln_file" "run: ./iocs.sh $input sta (mode $mode needs SUTURE's result)"
        if [ "$mode" = tree ]; then
            # tree mode takes the real paths (--result holds the SUTURE inputs and table.c).
            ( cd "$rw" && python3 main.py --binary "${arcs_bin_file}" --result "${arcs_i_result_path}"; exit $? )
        else
            # binary mode still derives result_dir from the grandparent of --binary (result/<t>.out).
            ( cd "$rw" && python3 main.py --binary "${arcs_result_path}/${input}.out"; exit $? )
        fi
    else
        ( cd "${rewrite_path}" && python3 main.py --binary "${input}.out" --directory "${arcs_i_result_path}"; exit $? )
    fi
    local rc=$?
    [ $rc -eq 0 ] || die "rewriter exited with status $rc"
    need "$arcs_i_result_path/table.c" "the rewriter did not write table.c"
}

link()
{
    echo "Build the compartment table and the rewritten binary"
    need "$arcs_i_result_path/table.c" "the rewriter did not write table.c"
    ( cd "${arcs_i_result_path}" && make lib && make "${input}.new" ) || die "link failed"
}

run()
{
    need "$arcs_i_result_path/${input}.new" "run: ./iocs.sh $input link"
    ( cd "${arcs_i_result_path}" && LD_PRELOAD=./lib/table.so "./${input}.new" "${IOCS_RUN_ARGS[@]+"${IOCS_RUN_ARGS[@]}"}" )
}

stage()
{
    case $1 in
        tools|build|bitcode|dta|sta|rewrite|link|run) "$1" ;;
        all) build; dta; sta; rewrite; link ;;
        *) die "unknown stage: $1" ;;
    esac
}

if [ $# -gt 0 ]; then
    for s in "$@"; do stage "$s"; done
    exit 0
fi

options=("Build" "Taint" "Analyze" "Rewrite")
while true; do
    select option in "${options[@]}" Quit
    do
        case $REPLY in
            1) echo "Selected $option"; tools; build; break;;
            2) echo "Selected $option"; bitcode; dta; break;;
            3) echo "Selected $option"; sta; break;;
            4) echo "Selected $option"; rewrite; link; break;;
            $((${#options[@]}+1))) echo "Finished!"; break 2;;
            *) echo "Wrong input"; break;
        esac;
    done
done
