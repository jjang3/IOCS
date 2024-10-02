# Library-related                                                                       
SHELL           = /bin/zsh
CC              = gcc
PIEFLAGS        = -no-pie -fno-pie
ASMFLAGS        = -save-temps=obj -fno-omit-frame-pointer -g -O3

# Directories
parent_dir      := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../)
result_dir      = ${parent_dir}/result

%.out: %.c   # This is for one file
	$(eval name := $(basename $@))

	@echo $(name)
	@echo $(parent_dir) $(result_dir)

	if [ ! -d $(result_dir)/$(name) ]; then \
		mkdir -p $(result_dir)/$(name); \
	fi

	cp libMakefile $(result_dir)/$(name)/Makefile

	# Compile the source file and generate the intermediate assembly file
	$(CC) $(ASMFLAGS) -S $< -o $(result_dir)/$(name)/$(name).s

	# Assemble the assembly file to an object file
	as $(result_dir)/$(name)/$(name).s -o $(result_dir)/$(name)/$(name).o

	# Link the object file to create the final executable
	$(CC) $(result_dir)/$(name)/$(name).o -o $(result_dir)/$(name)/$@

	# Remove intermediate files if needed
	rm -f $(result_dir)/$(name)/$(name).i

	# Create analysis file if it doesn't exist
	if [ ! -f "$(result_dir)/$(name)/$(name).analysis" ]; then \
		echo "main" > $(result_dir)/$(name)/$(name).analysis; \
	fi

	# Check if taint input file exists
	if [ ! -e $(result_dir)/$(name)/taint.in ]; then \
		echo "Taint Input File Doesn't exist"; \
	fi

clean:
	rm -rf lib *.o *.out *.i
