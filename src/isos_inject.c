#include <assert.h>
#include <bfd.h>
#include <err.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "argparser.h"
#include "elf_edit.h"
#include "verifbin.h"

int main(int argc, char *argv[]) {
    int err;
    struct arguments args = {
        .addr = NULL,
        .input_file = NULL,
        .machine_code_file = NULL,
        .new_section = NULL,
        .mef = NULL,
        .func_to_replace = NULL
    };

    argp_parse(&argp, argc, argv, 0, 0, &args);

    // Verifying that all the arguments are set
    if (args.new_section == NULL || args.addr == NULL || args.input_file == NULL || args.machine_code_file == NULL || args.mef == NULL) {
        errx(EXIT_FAILURE, "Error: All arguments have to be set\n\tisos-inject --usage\t for more informations");
    }

    // Declaring variable of the arguments.
    int64_t base_addr;
    bool mef;
    char *new_section;
    char *input_file;
    char *machine_code_file;
    char *func_to_replace;

    // Initialize the arguments with valid value
    int64_t tmp = atoi(args.mef);
    if (tmp != 0 && tmp != 1) {
        errx(EXIT_FAILURE, "Error: Argument -b --bool has to be 0 or 1");
    }
    mef = (tmp == 0) ? false : true;

    char *err_strtol;
    tmp = strtol(args.addr, &err_strtol, 0);
    if (*err_strtol != '\0') {
        errx(EXIT_FAILURE, "Error: Argument -a should be hexadecimal 0xINT or decimal INT");
    }

    if (tmp < 0) {
        errx(EXIT_FAILURE, "Error: Argument -a --addr has to be >= 0");
    }

    base_addr = tmp;

    new_section = args.new_section;
    input_file = args.input_file;
    machine_code_file = args.machine_code_file;
    func_to_replace = args.func_to_replace;

    if (mef == 0 && func_to_replace == NULL){
        errx(EXIT_FAILURE, "Error: Argument function name -d is required when -m is 0\n");
    }

#ifdef DEBUG
    printf("Debug: main:\n");
    printf("\tbase_addr = 0x%lx\n", base_addr);
    printf("\tmef = %d\n", mef);
    printf("\tmachine_code_file = %s\n", machine_code_file);
    printf("\tnew_section = %s\n", new_section);
    printf("\tinput_file = %s\n", input_file);
    printf("\tfunc_to_replace = %s\n", func_to_replace);
#endif 

    // opening the binary with libbfd
    bfd_init();
    bfd *binary = bfd_openr(input_file, NULL);
    if (binary == NULL) {
        errx(EXIT_FAILURE, "Error: bdf_openr couldnt open the input_file");
    }
    // Verify the binary
    // format ELF, Executable, 64bits
    if (verify_binary(binary)) {
        printf("Binary '%s' is valid\n", input_file);
    }
    else {
        bfd_close(binary);
        printf("Binary '%s' is not valid: It needs to be an EXEC type ELF file, for 64bits architecture\n", input_file);
        return -1;
    }
    bfd_close(binary);

    // Challenge 3: we append the code to the elf file and compute the base address for ELF address obligation
    size_t begin_offset = append_code(input_file, machine_code_file);
    base_addr += (begin_offset - base_addr) % ELF_ALIGN;
    printf("begin_offset: 0x%08lx base_addr recomputed for alignment: 0x%08lx\n", begin_offset, base_addr);

    // Now we will modify the ./date file so let's load it into the memory
    // first we open the file
    int fd = open(input_file, O_RDWR);
    if (fd == -1) {
        errx(EXIT_FAILURE, "Error: %s: couldn't open '%s' file\n", argv[0], input_file);
    }

    // we gather the size of the file
    struct stat file_stat;
    err = fstat(fd, &file_stat);
    if (err == -1) {
        close(fd);
        errx(EXIT_FAILURE, "Error: %s: fstat failed\n", argv[0]);
    }
    off_t file_size = file_stat.st_size;

    // then we bind it into the memory with mmap
    void *file_begin = mmap(0, file_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (file_begin == MAP_FAILED) {
        errx(EXIT_FAILURE, "Error: %s: mmap failed\n", argv[0]);
    }

    //Challenge 2: Find the index of the segment to write the injected code
    int index_pt_note = find_pt_note_index(file_begin);
    if (index_pt_note == -1) {
        munmap(file_begin, file_size);
        return -1;
    }
    
    //Challenge 4: we modify the section header of .note.ABI-tag to be synchronized with the new code appended
    int index_section = overwrite_section_hdr(file_begin, file_size, new_section, base_addr, begin_offset);
    if (index_section == -1) {
        munmap(file_begin, file_size);
        return -1;
    }

    // Challenge 5: we sort the section
    sort_section_hdr(file_begin, index_section);

    // Challenge 6: modifying the segment header of the segment to load
    size_t size_injected = file_size - begin_offset;
    overwrite_program_hdr(file_begin, index_pt_note, size_injected, begin_offset, base_addr);

    if (mef) {
        // Challenge 7.1: when the injected code work for the entrypoint and go back to the program
        // The user have to well configure its code to jump to the original entrypoint
        modify_entry_point(file_begin, base_addr);
    }
    else {
        // Challenge 7.2: More interesting, the user choose a dynamic function to hook in the got.
        // the function execute the injected code instead of its normal code.
        err = replace_in_got(file_begin, base_addr, func_to_replace);
        if (err == -1) {
            munmap(file_begin, file_size);
            return -1;
        }
    }

    err = munmap(file_begin, file_size);
    if (err == -1) {
        errx(EXIT_FAILURE, "Error: %s: munmap failed\n", argv[0]);
    }

    return 0;
}