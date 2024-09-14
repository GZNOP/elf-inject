#include <elf.h>
#include <err.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "elf_edit.h"

#ifdef DEBUG
static void print_elf_program_header(Elf64_Phdr *program_header) {
    // print program header like readelf
    printf("  Type:                              ");

    switch (program_header->p_type) {
        case PT_NULL:
            printf("NULL\n");
            break;
        case PT_LOAD:
            printf("LOAD\n");
            break;
        case PT_DYNAMIC:
            printf("DYNAMIC\n");
            break;
        case PT_INTERP:
            printf("INTERP\n");
            break;
        case PT_NOTE:
            printf("NOTE\n");
            break;
        case PT_SHLIB:
            printf("SHLIB\n");
            break;
        case PT_PHDR:
            printf("PHDR\n");
            break;
        case PT_TLS:
            printf("TLS\n");
            break;
        default:
            printf("<unknown: %u>\n", program_header->p_type);
            break;
    }

    printf("  Offset:                           %#lx\n", program_header->p_offset);
    printf("  VirtAddr:                         %#lx\n", program_header->p_vaddr);
    printf("  PhysAddr:                         %#lx\n", program_header->p_paddr);
    printf("  FileSiz:                          %#lx (bytes)\n", program_header->p_filesz);
    printf("  MemSiz:                           %#lx (bytes)\n", program_header->p_memsz);
    printf("  Flags:                            %#x\n", program_header->p_flags);
    printf("  Align:                            %#lx\n\n", program_header->p_align);
}

static void print_elf64_shdr(Elf64_Shdr *shdr, char *section_strings) {
    printf("Section header:\n");
    printf("  Section name: %s\n", section_strings + shdr->sh_name);
    printf("  Section type: %x\n", shdr->sh_type);
    printf("  Section flags: %lx\n", shdr->sh_flags);
    printf("  Virtual address: %lx\n", shdr->sh_addr);
    printf("  File offset: %lx\n", shdr->sh_offset);
    printf("  Section size: %lx\n", shdr->sh_size);
    printf("  Link section index: %x\n", shdr->sh_link);
    printf("  Additional info: %x\n", shdr->sh_info);
    printf("  Section alignment: %lx\n", shdr->sh_addralign);
    printf("  Entry size: %lx\n\n", shdr->sh_entsize);
}
#endif

// Find the first PT_NOTE type segment of the file filename and return its index
int find_pt_note_index(void *file_begin) {

    Elf64_Ehdr *exec_head = (Elf64_Ehdr *)file_begin;
    // the index that will be the offset of the first program header of type PT_NOTE
    int index_pt;
    Elf64_Half nb_program_header = exec_head->e_phnum;
    // We store the first program_header
    Elf64_Phdr *program_header = (Elf64_Phdr *)(((uintptr_t)file_begin) + exec_head->e_phoff);

#ifdef DEBUG
    printf("Debug: find_pt_note_index: Searching for PT_NOTE segment\n");
#endif

    // Loop over the program header to find the PT_NOTE segment
    for (index_pt = 0; index_pt < nb_program_header; index_pt++) {
#ifdef DEBUG
        printf("INDEX : %d\n", index_pt);
        print_elf_program_header(program_header);
#endif
        if (program_header->p_type == PT_NOTE) {
            break;
        }
        program_header = program_header + 1;
    }

    // We parsed all the program_header without finding PT_NOTE
    if (index_pt >= nb_program_header) {
        fprintf(stderr, "Error: No program header of type PT_NOTE found\n");
        return -1;
    }

    printf("find_pt_note_index: PT_NOTE segment header found, index: %d\n", index_pt);
    return index_pt;
}

size_t append_code(char *dst_file, char *src_file) {
    // append the code of src_file to the end of the dst_file
    // return the offset of the beginning of the injection

    // Opening the input file in append mode and add the other one
    int dst = open(dst_file, O_RDWR | O_APPEND);
    if (dst == -1) {
        errx(EXIT_FAILURE, "Error: append_code: Couldn't open '%s' file\n", dst_file);
    }

    size_t begin_offset = lseek(dst, 0, SEEK_END);

    // Opening the file with the code to append
    int src = open(src_file, O_RDONLY);
    if (src == -1) {
        close(dst);
        errx(EXIT_FAILURE, "Error: append_code: Couldn't open '%s' file\n", src_file);
    }

    // We use a buffer to read from src and write the bytes read to dst
    char buf[SIZE_BUF];
    unsigned int b_read, b_written;

    while ((b_read = read(src, buf, SIZE_BUF)) > 0) {
        b_written = write(dst, buf, b_read);

        // If we didn't achieve to copy the all buffer, we raise an error
        if (b_written != b_read) {
            close(dst);
            close(src);
            errx(EXIT_FAILURE, "Error: append_code: Error while writing in '%s'\n", dst_file);
        }
    }
    close(dst);
    close(src);

    if (b_read < 0) {
        errx(EXIT_FAILURE, "Error: append_code: Error while reading in '%s'\n", src_file);
    }

    printf("append_code: code from '%s' appended to '%s' successfully\n", src_file, dst_file);

    return begin_offset;
}

static void update_section(Elf64_Shdr *sect_header, char *strtab, char *new_sect_name, size_t baddr, off_t offset, size_t size) {
    sect_header->sh_addr = baddr;
    sect_header->sh_addralign = 16;
    sect_header->sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    sect_header->sh_offset = offset;
    sect_header->sh_type = SHT_PROGBITS;
    sect_header->sh_size = size;

    size_t len = strlen(&strtab[sect_header->sh_name]);
    for (size_t i = 0; i < len; i++) {
        strtab[sect_header->sh_name + i] = new_sect_name[i];
    }
}

static int get_sect_hdr_index(Elf64_Shdr *sect_head, char *shstrtab, char *to_get, Elf64_Half nb_sect) {
    // return the index of the section header 'to_get'
    for (int i = 0; i < nb_sect; i++) {
        if (strcmp(to_get, &shstrtab[sect_head[i].sh_name]) == 0) {
            return i;
        }
    }
    return -1;
}

int overwrite_section_hdr(void *file_begin, off_t file_size, char *new_sect_name, uint64_t baddr, size_t offset) {
    Elf64_Ehdr *exec_header = file_begin;
    Elf64_Shdr *sect_header = (Elf64_Shdr *)(((intptr_t)file_begin) + exec_header->e_shoff); // the first section header
    Elf64_Half index_shstrtab = exec_header->e_shstrndx;                                     // index of .shstrtab
    Elf64_Half nb_section = exec_header->e_shnum;                                            // number of section header
    char *shstrtab = ((char *)file_begin) + sect_header[index_shstrtab].sh_offset;

    // get the section to replace
    int index_replace = get_sect_hdr_index(sect_header, shstrtab, SECTION_TO_REPLACE, nb_section);

    // error if we didnt find the section to replace
    if (index_replace == -1) {
        fprintf(stderr, "Error: '%s' section header not found\n", SECTION_TO_REPLACE);
        return -1;
    }
    update_section(&sect_header[index_replace], shstrtab, new_sect_name, baddr, offset, file_size - offset);

#ifdef DEBUG
    printf("INDEX: %d\n", index_replace);
    print_elf64_shdr(&sect_header[index_replace], shstrtab);
    printf("Section '%s' replaced by '%s'\n", SECTION_TO_REPLACE, &shstrtab[sect_header[index_replace].sh_name]);
#endif

    return index_replace;
}

static void swap(Elf64_Shdr *a, Elf64_Shdr *b) {
    Elf64_Shdr tmp;
    tmp = *a;
    *a = *b;
    *b = tmp;
}

// the index of the modified section header
int sort_section_hdr(void *file_begin, unsigned int i) {
    // Now we make one iteration of a sorting algorithm to place the overwritted section hdr
    // depending of the new address of where the section will be loaded
    Elf64_Ehdr *exec_header = file_begin;
    Elf64_Shdr *sect_header = (Elf64_Shdr *)(void *)(((char *)file_begin) + exec_header->e_shoff); // the first section header
    Elf64_Half nb_section = exec_header->e_shnum;

    if (i <= 0 || i >= nb_section) {
        fprintf(stderr, "Error: sort_section_hdr: i_sect index out of range\n");
        return -1;
    }

    unsigned int i_save = i;

    // the address has go to the right of its current position
    // sect_header[i_sect + 1].sh_addr != 0 : some specials sections at the end have address 0. So we stop before them
    while (i < nb_section - 1 && sect_header[i + 1].sh_addr != 0 && sect_header[i].sh_addr > sect_header[i + 1].sh_addr) {
        swap(&sect_header[i], &sect_header[i + 1]);
        i++;
    }

    // the address has to go to the left of its current position
    // > 1 to avoid the NULL section header
    while (i > 1 && sect_header[i].sh_addr < sect_header[i - 1].sh_addr) {
        swap(&sect_header[i], &sect_header[i - 1]);
        i--;
    }

    /*
    [sh_NULL, sh_1, ... , sh_modifed , ... , sh_x, special_sh...]

    In this part we update the sh_link of sections headers if needed.
    We browse all the sections potentially moved again (not NULL and not the special one with addresses 0)
    We know that because we modified 1 section header, we only have one iteration of a sort algorithm, so the 
    already sorted sections move at maximum from 1 cells. Thus the sh_link field, is incremented by 1 or decremented by 1 
    or the same.
    We need to check, for each section header. If the sh_link of the current header is in the interval of the swapped section headers.
    We decrement if the modified section header swapped to the right
    We increment if the modified section header swapped to the left

    */

    // check the direction of the swap propagation
    // case right
    if (i_save < i) {
        // browse all the section headers
        for (int j = 1; j + 1 < nb_section && sect_header[j + 1].sh_addr != 0; j++) {
            // check if the link fields concerns modified sections headers and adapt
            if (i_save < sect_header[j].sh_link && sect_header[j].sh_link <= i) {
                sect_header[j].sh_link--;
            }
            // specific case if the modified section was linked by other sections headers
            else if (sect_header[j].sh_link == i_save) {
                sect_header[j].sh_link = i;
            }
        }
    }
    // same thing but for the left
    else if (i_save > i) {
        for (int j = 1; j + 1 < nb_section && sect_header[j + 1].sh_addr != 0; j++) {
            if (i <= sect_header[j].sh_link && sect_header[j].sh_link < i_save) {
                sect_header[j].sh_link++;
            }
            else if (sect_header[j].sh_link == i_save) {
                sect_header[j].sh_link = i;
            }
        }
    }

#if DEBUG
    printf("Debug: sort_section_hdr: sections headers sorted\n");
#endif

    return 0;
}

void overwrite_program_hdr(void *file_begin, int i_ph, size_t size_injected, size_t begin_offset, int64_t base_addr) {
    Elf64_Ehdr *exec_head = (Elf64_Ehdr *)file_begin;
    Elf64_Phdr *prog_head = (Elf64_Phdr *)(((intptr_t)file_begin) + exec_head->e_phoff);

    // Update the value of the PT_NOTE segment
    prog_head[i_ph].p_align = ELF_ALIGN;
    // we only need what we add (no uninitialized variable like .bss)
    prog_head[i_ph].p_filesz = size_injected;
    prog_head[i_ph].p_memsz = size_injected;
    // executable flag
    prog_head[i_ph].p_flags = PF_R | PF_X;
    // Start of our code
    prog_head[i_ph].p_offset = begin_offset;
    // Loadable segment
    prog_head[i_ph].p_type = PT_LOAD;

    // hosted environment so we do not decide the physical address
    // we put the same to be coordinate with the other prog hdrs
    prog_head[i_ph].p_paddr = base_addr;
    prog_head[i_ph].p_vaddr = base_addr;

#ifdef DEBUG
    printf("Debug: overwrite_program_hdr: segment overwritten\n");
#endif
}

void modify_entry_point(void *file_begin, int64_t new_entry_point) {
    Elf64_Ehdr *exec_head = (Elf64_Ehdr *)file_begin;
    exec_head->e_entry = new_entry_point;
#ifdef DEBUG
    printf("Debug: modify_entry_point: entry point modified.\n");
#endif
}

int replace_in_got(void *file_begin, uint64_t base_addr, char *func_name) {
    // the case we want to replace a function in dynamic library
    Elf64_Ehdr *exec_header = file_begin;
    Elf64_Shdr *sect_header = (Elf64_Shdr *)(((intptr_t)file_begin) + exec_header->e_shoff); // the first section header
    Elf64_Half index_shstrtab = exec_header->e_shstrndx;                                     // index of .shstrtab
    Elf64_Half nb_section = exec_header->e_shnum;                                            // number of section header
    char *shstrtab = ((char *)file_begin) + sect_header[index_shstrtab].sh_offset;

    // get all the indexes
    int i_dynsym = get_sect_hdr_index(sect_header, shstrtab, SH_DYNTAB, nb_section);
    int i_gotplt = get_sect_hdr_index(sect_header, shstrtab, SH_GOTPLT, nb_section);
    int i_dynstr = get_sect_hdr_index(sect_header, shstrtab, SH_DYNSTR, nb_section);
    int i_relaplt = get_sect_hdr_index(sect_header, shstrtab, SH_RELAPLT, nb_section);

    if (i_dynsym == -1 || i_gotplt == -1 || i_dynstr == -1 || i_relaplt == -1) {
        fprintf(stderr, "Error: replace_in_got: .dynsym or .rela.plt or .dynstr or .got.plt not found\n");
        return -1;
    }

    int nb_relaplt = sect_header[i_relaplt].sh_size / sect_header[i_relaplt].sh_entsize; // total_size / entry_size
    // We take the beginning of each section we'll use
    Elf64_Rela *relaplt = (Elf64_Rela *)(((uintptr_t)file_begin) + sect_header[i_relaplt].sh_offset); // .rela.plt section
    Elf64_Sym *dynsym = (Elf64_Sym *)(((uintptr_t)file_begin) + sect_header[i_dynsym].sh_offset);     // .dynsym section
    char *dynstr = (char *)(((uintptr_t)file_begin) + sect_header[i_dynstr].sh_offset);               // .dynstr section
    int64_t *gotplt = (int64_t *)(((uintptr_t)file_begin) + sect_header[i_gotplt].sh_offset);         // .got.plt section

    // to be coordinate with the symtab value (probably a header)
    gotplt = gotplt + 3;

    // parse the .rela.plt that contains the dynamic function symbol and their index used in the .got.plt
    // we check if the current symbol is the one searched. Get it's index for the .got.plt and replace the normal address by the
    // address of the injected code.
    // Here it's a little bit tricky because we don't rely on the dynsym index to know the index in the gotplt.
    // We rely
    int i_func;
    int i_sym;
    for (i_func = 0; i_func < nb_relaplt; i_func++) {
        i_sym = ELF64_R_SYM(relaplt[i_func].r_info);
#ifdef DEBUG
        printf("Debug: i: %d\tisym: %d\t name: %s\tgotpltaddr: %lx\n", i_func, i_sym, &dynstr[dynsym[i_sym].st_name], gotplt[i_func]);
#endif
        if (strcmp(func_name, &dynstr[dynsym[i_sym].st_name]) == 0) {
            break;
        }
    }

    if (i_func >= nb_relaplt) {
        fprintf(stderr, "Error: replace_in_got: function '%s' not found in .rela.plt\n", func_name);
        return -1;
    }

    printf("replace_in_got: entry %d '%s' of .got.plt section modified: 0x%lx replaced by 0x%lx", i_func, func_name, gotplt[i_func], base_addr);
    gotplt[i_func] = base_addr;
    return 0;
}