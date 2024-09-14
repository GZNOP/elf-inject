vpath %.c src
SRC_FILES= isos_inject.c argparser.c verifbin.c elf_edit.c

# Directories used
BIN_DIR=bin/
SRC_DIR=src/
INCLUDE_DIR=include/
OBJ_DIR=obj/

#SRC_FILES=$(SRC_DIR)isos_inject.c $(SRC_DIR)argparser.c $(SRC_DIR)verifbin.c $(SRC_DIR)execheader.c
OBJ_FILES=$(OBJ_DIR)argparser.o $(OBJ_DIR)isos_inject.o $(OBJ_DIR)verifbin.o $(OBJ_DIR)elf_edit.o

ASM=nasm
CC=gcc
CFLAGS=-g -fPIE -O2 -Warray-bounds -Wsequence-point -Walloc-zero -Wnull-dereference \
-Wpointer-arith -Wcast-qual -Wcast-align=strict -I$(INCLUDE_DIR)
LDFLAGS=-Wl,--strip-all
LLIB=-lbfd
DEBUG=-DDEBUG

.PHONY: all help clean

all: isos-inject build_dependencies $(BIN_DIR)injected-code-ep $(BIN_DIR)injected-code-got

build_dependencies: $(SRC_FILES:.c=.dep)
	@cat $^ > make.test
	@rm $^ 

# Create the makefile dependencies of the project
%.dep: %.c
	gcc -I $(INCLUDE_DIR) -MM -MF $@ $<

# Compile the assembly of the injected code
$(BIN_DIR)injected-code-ep: $(SRC_DIR)injected_code7_1.s
	nasm -f bin $^ -o $@

$(BIN_DIR)injected-code-got: $(SRC_DIR)injected_code7_2.s
	nasm -f bin $^ -o $@

# Create the object files
$(OBJ_DIR)isos_inject.o : $(SRC_DIR)isos_inject.c $(INCLUDE_DIR)argparser.h $(INCLUDE_DIR)\
						$(INCLUDE_DIR)verifbin.h $(INCLUDE_DIR)elf_edit.h 
	$(CC) $(DEBUG) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)argparser.o : $(SRC_DIR)argparser.c $(INCLUDE_DIR)argparser.h
	$(CC) $(DEBUG) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)verifbin.o : $(SRC_DIR)verifbin.c $(INCLUDE_DIR)verifbin.h
	$(CC) $(DEBUG) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)elf_edit.o : $(SRC_DIR)elf_edit.c $(INCLUDE_DIR)elf_edit.h
	$(CC) $(DEBUG) $(CFLAGS) -c $< -o $@



# make the binary
isos-inject: $(OBJ_FILES)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LLIB)

clean:
	rm $(OBJ_DIR)* isos-inject $(BIN_DIR)*

help:
	@echo "isos-inject:\tto create the binary of the project"
	@echo "build_dependencies:\tto build the dependencies of the project in the make.test file"
	@echo "clean:\tto remove the binary and .o files"
	@echo "help: to display this help"
