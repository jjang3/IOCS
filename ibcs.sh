# IBCS Script
#!/bin/bash

PS3="Select options: "
input=$1
CFLAGS="-O3 -gdwarf-2"

options=("Build File" "Build Dir." "Rewrite File" "Rewrite Dir." "Remove Result")

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
dwarf_path=${current_path}/dwarf_analysis

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
    echo "Build a file"
    if [ ! -f "$ibcs_bin_file" ]; then
        echo "Generate the original file"
        cd ${ibcs_input_path} && make ${input}.out
    fi
}

build_dir()
{
    echo "Build a directory"

    if [ ! -d "$ibcs_input_result" ]; then
        echo "Input result directory doesn't exist, creating it."
        mkdir $ibcs_input_result
    else
        echo "Input result directory exists, cleaning it."
        rm -rf "${ibcs_input_result:?}/"*
    fi


    # Copy the Makefile and source files into the input result directory
    cd "${ibcs_input_path}" || { echo "Failed to change directory to ${ibcs_input_path}"; exit 1; }
    cp dirMakefile "$ibcs_input_result/Makefile"
    
    cd "${ibcs_input_path}/${input}" || { echo "Failed to change directory to ${ibcs_input_path}/${input}"; exit 1; }
    cp -r ./* "$ibcs_input_result/"

    # Change to the input result directory where the Makefile is now present
    cd "$ibcs_input_result" || { echo "Failed to change directory to ${ibcs_input_result}"; exit 1; }

    # Create or overwrite the .analysis file
    analysis_file="${ibcs_input_result}/${input}.analysis"
    echo "main" > "$analysis_file"

    # Generate assembly files for each .c file
    for file in *.c; do
        if [ -f "$file" ]; then
            base_name=$(basename "$file" .c)
            echo "Generating assembly for $file"
            make "${base_name}.s"
            make "${base_name}.o"
            rm "${base_name}.i"
        fi
    done
}

# dwarf_analysis()
# {
#     echo "Extract DWARF information"
#     cd ${dwarf_path} && python3 main.py --binary ${input}.out

# }
# 3) echo "Selected $option": dwarf_analysis; break;;
            

rewrite()
{
    if [ ! -d "$ibcs_result_path" ]; then
        echo "Result directory doesn't exist"
        mkdir $ibcs_result_path
    fi

    echo "Rewrite the assembly code" 
    cd ${rewriter_path} && python3 main.py --binary ${input}.out
    # cd ${ibcs_input_result} && make lib && make ${input}.new
}

rewrite_dir()
{
    echo "Rewrite the assembly codes for the target directory" 
    if [ ! -d "$ibcs_result_path" ]; then
        echo "Result directory doesn't exist"
        mkdir $ibcs_result_path
    fi

    cd ${rewriter_path} && python3 main.py --dir ${ibcs_input_result}
}

remove_result()
{
    echo "Remove the result directory for the target"
    if [ -d "$ibcs_input_result" ]; then
        echo "Directory ${ibcs_input_result} found; Removing it"
        rm -rf $ibcs_input_result
    fi
}

while true; do
    select option in "${options[@]}" Quit
    do
        case $REPLY in
            1) echo "Selected $option"; build; break;;
            2) echo "Selected $option"; build_dir; break;;
            3) echo "Selected $option"; rewrite; break;;
            4) echo "Selected $option"; rewrite_dir; break;;
            5) echo "Selected $option"; remove_result; break;;
            $((${#options[@]}+1))) echo "Finished!"; break 2;;
            *) echo "Wrong input"; break;
        esac;
    done
done
