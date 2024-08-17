# This script is used for coreutils rewriting purpose (e.g., could be expanded for other applications?)
#!/bin/bash

PS3="Select options: "
input=$1

options=("Migrate" "Analyze" "Rewrite" "Compile")

# This is coreutils path
coreutils_build_path="/home/jaewon/coreutils_bu/new_build"
coreutils_src_path="/home/jaewon/coreutils_bu/new_build/src"

# This is used to setup test path
grandp_path=$( cd ../../"$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
parent_path=$( cd ../"$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
current_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )

ibcs_input_path=${parent_path}/input

ibcs_result_path=${parent_path}/result

# Input Result Related Paths
ibcs_input_result=${ibcs_result_path}/$1

# Rewriter Path
rewriter_path=${parent_path}/asm_rewriter

# https://www.maizure.org/projects/decoded-gnu-coreutils/index.html

migrate()
{
    echo "Migrate select assembly file (if input file exists)" 
    if [ -z ${coreutils_src_path}/${input}.s ]
    then
        echo "No source file, please use other option"
        exit
    fi

    if [ ! -d "$ibcs_result_path" ]; then
        echo "Result directory doesn't exist"
        mkdir $ibcs_result_path
    fi
    
    if [ ! -d "$ibcs_input_result" ]; then
        mkdir $ibcs_input_result
    fi

    if [ ! -z ${ibcs_input_result}/${input}.s ]
    then
        echo "No source file in the result directory"
        cp ${coreutils_src_path}/${input}.s ${ibcs_input_result}
    fi

    cp ${coreutils_src_path}/${input} ${coreutils_src_path}/${input}.def
    cp ${coreutils_src_path}/${input}.def $ibcs_input_result/${input}.out
    cp ${coreutils_src_path}/${input}.def $ibcs_input_result/${input}.def
    cp ${coreutils_src_path}/${input}.s ${coreutils_src_path}/${input}.s.bak
    cp ${coreutils_src_path}/${input}.s.bak $ibcs_input_result
    if [ ! -e ${ibcs_input_result}/${input}.analysis ] 
	then 
		echo "Doesn't exist" 
	else
		rm ${ibcs_input_result}/${input}.analysis
	fi 
    printf "main" >> $ibcs_input_result/${input}.analysis
}

analyze()
{
    echo "Find vulnerable data"
}

rewrite()
{
    echo "Rewrite"
    if [ -f ${result_path}/${input}.s.bak ]
    then 
        echo "Original file found, overwrite the existing asm file"
        cp ${result_path}/${input}.s.bak ${ibcs_input_result}/${input}.s
    fi
    sleep 1.5
    cd ${rewriter_path} && python3 main.py --binary ${input}.out 
    # python3 binary_patch.py --binary ${input}.def --fun fun.list
    #--fun list.out --dir=tests/${input}
}

compile()
{
    echo "Migrate back to coreutils and compile" 
    if [ -z ${result_path}/${input}.s ]
    then
        echo "No source file, please use other option"
        exit
    fi
    cp ${input_path}/libMakefile ${result_path}/Makefile
    cd ${result_path}
    make lib
    cp -rf ${result_path}/lib ${coreutils_src_path}
    echo ${result_path}/${input}.s
    as -o ${coreutils_src_path}/${input}.o ${result_path}/${input}.s
    sleep 3
    cd ${coreutils_build_path}
    pwd
    make src/${input}
}

while true; do
    select option in "${options[@]}" Quit
    do
        case $REPLY in
            1) echo "Selected $option"; migrate; break;;
            2) echo "Selected $option"; analyze; break;;
            3) echo "Selected $option"; rewrite; break;;
            4) echo "Selected $option"; compile; break;;
            $((${#options[@]}+1))) echo "Finished!"; break 2;;
            *) echo "Wrong input"; break;
        esac;
    done
done
