# IBCS Script
#!/bin/bash

PS3="Select options: "
input=$1

CFLAGS="-O0 -gdwarf-2"

options=("Build" "Taint" "Analyze Taint" "DWARF" "Rewrite")

# Folder paths
grandp_path=$( cd ../../"$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
parent_path=$( cd ../"$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
current_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )

# Taint Analysis Path (Using SUTURE for the IBCS Purpose)
taint_path=${current_path}/taint_analysis

# PIN Instrumentation Path
pin_path=${current_path}/pin-3.27_build

# Utility Scripts Path
utility_path=${current_path}/utilities

# Input Path 
ibcs_input_path=${current_path}/input

# Result Path
ibcs_result_path=${current_path}/result

# Rewriter Path
rewriter_path=${current_path}/asm_rewriter

# Input Result Related Paths
ibcs_input_result=${ibcs_result_path}/$1
ibcs_bin_file=${ibcs_input_result}/$1.out
ibcs_out_file=${ibcs_input_result}/${1}_ibcs.out
ibcs_dwarf_file=${ibcs_input_result}/$1.dwarf
ibcs_analysis_file=${ibcs_input_result}/$1.analysis

build()
{
    echo "Build" 
}

taint()
{
    echo "Taint analysis"
}

taint_analyze()
{
    echo "Find vulnerable data"
}

dwarf()
{
    echo "Extract DWARF information"
}

rewrite()
{
    if [ ! -d "$ibcs_result_path" ]; then
        echo "Result directory doesn't exist"
        mkdir $ibcs_result_path
    fi

    echo "Rewrite the assembly code" 
    if [ ! -f "$ibcs_bin_file" ]; then
        echo "Generate the original file"
        cd ${ibcs_input_path} && make ${input}.out
    fi
    cd ${rewriter_path} && python3 main.py --binary ${input}.out
    # cd ${ibcs_input_result} && make lib && make ${input}.new
}

while true; do
    select option in "${options[@]}" Quit
    do
        case $REPLY in
            1) echo "Selected $option"; build; break;;
            2) echo "Selected $option"; taint; break;;
            3) echo "Selected $option"; taint_analyze; break;;
            4) echo "Selected $option": dwarf; break;;
            5) echo "Selected $option"; rewrite; break;;
            $((${#options[@]}+1))) echo "Finished!"; break 2;;
            *) echo "Wrong input"; break;
        esac;
    done
done
