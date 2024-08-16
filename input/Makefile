#Library-related                                                                       
SHELL           = /bin/zsh
CC              = gcc
PIEFLAGS 		= -no-pie -fno-pie
ASMFLAGS		= -O0 -gdwarf-2 -c -save-temps=obj
INTELFLAGS		= -O0 -gdwarf-2 -S -masm=intel

parent_dir := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../)
result_dir = ${parent_dir}/result

%.out: %.c	# This is for one file
	$(eval name := $(basename $@))

	@echo $(name)
	@echo $(parent_dir) $(result_dir)

	if [ ! -d $(result_dir)/$(name) ]; then \
		mkdir -p $(result_dir)/$(name); \
	fi

	cp libMakefile $(result_dir)/$(name)/Makefile
	$(CC) $(ASMFLAGS) $< -o $(result_dir)/$(name)/$@
	rm -f $(result_dir)/$(name)/$(name).i
	echo "main" > $(result_dir)/$(name)/$(name).analysis
	as $(result_dir)/$(name)/$(name).s -o $(result_dir)/$(name)/$(name).o
	$(CC) -O0 -gdwarf-2 $(result_dir)/$(name)/$(name).o -o $(result_dir)/$(name)/$@

	if [ ! -e $(result_dir)/$(name)/taint.in ]; then \
		echo "Taint Input File Doesn't exist"; \
	fi

clean:
	rm -rf lib *.o *.out *.i