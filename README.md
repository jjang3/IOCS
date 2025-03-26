# Input-Oriented Compartmentalization System (IOCS)

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
└── iocs.sh
```


# IOCS Script Directions
1. Insert a source file into the `input` directory (e.g., `tiny.c`).
2. Run the IOCS script with the input name:
   ```bash
   bash iocs.sh tiny
   ```
3. Follow the prompts to select an option.

# Dockerfile Directions
1. Build the Docker image:
   ```bash
   docker build -t iocs:latest .
   ```
2. Run the Docker container:
   ```bash
   docker run -v $HOME/binaryninja:/root/binaryninja -it --name iocs_debug iocs:latest /bin/zsh
   ```
3. If you exit the container, restart it by checking the container ID:
   ```bash
   docker ps -a
   ```
   Then restart and re-attach:
   ```bash
   docker start <container-id>
   docker exec -it <container-id> /bin/zsh
   ```
4. Once inside the Docker environment, activate the virtual environment:
   ```bash
   source /root/venv/bin/activate
   ```


# Coreutils Directions
1. In the `core.sh` file (located in `utility_scripts`), update the variables to reflect the correct path to `coreutils` (e.g., `$HOME/coreutils`).
2. Run the `core.sh` script:
   ```bash
   bash core.sh <program>
   ```
   Example:
   ```bash
   bash core.sh yes
   ```
3. Before rewriting, move the file into the `IOCS/result/coreutils_bin` folder.
4. Use the `rewrite` option to rewrite the code.
5. Use the `compile` option to rewrite the assembly file in `IOCS/result/coreutils_bin`. This will copy necessary files back to the `coreutils` folder (defined by `$coreutils_src_path` in `core.sh`).

## Directions for the NGINX

---
