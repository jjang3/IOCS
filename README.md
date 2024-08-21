# Input-Based Compartmentalization System (IBCS)

## What's included

```
./
├── taint_analysis (to-do)
├── input (for single source file like tiny.c)
├── utility-scripts
|       ├── core.sh
|       └── ...
|
├── asm_rewriter
|        ├── src 
|        └── main.py (python3 main.py --binary)
|
├── dwarf_analysis
|        ├── src 
|        └── main.py (python3 main.py --binary)
|
└── ibcs.sh
```

## Directions
1) Insert a source file into the `input` directory (e.g., `tiny.c`)
2) Execute the IBCS script with the input name (e.g., `bash ibcs.sh tiny`)
3) Select the option prompted

## Directions for the Coreutils
1) Update the variables of the `core.sh`file in the `utility_scripts` folder with the proper path towards the `coreutils` (e.g., `$HOME/coreutils`)
2) Before rewriting, you need to migrate the file into the `IBCS/result/coreutils_bin` folder
3) Then rewrite the code by using the `rewrite` option
4) `compile` option will rewrite the assembly file in the `IBCS/result/coreutils_bin` folder, which will then copy necessary files back to the `coreutils` folder (which is the variable `$coreutils_src_path` in the `core.sh`)
---