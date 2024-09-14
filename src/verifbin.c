#include <bfd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "verifbin.h"

static bool is_ELF(bfd *binary) {
    // Return true if the binary is of type elf
    enum bfd_flavour flav = bfd_get_flavour(binary);
#ifdef DEBUG
    printf("Debug: flav == bfd_target_elf_flavour : %d\n", (flav == bfd_target_elf_flavour) && bfd_check_format(binary, bfd_object));
#endif
    return (flav == bfd_target_elf_flavour) && bfd_check_format(binary, bfd_object);
}

static bool is_64bit(bfd *binary) {
    // we get the architecture and check it.
    //const bfd_arch_info_type * arch = bfd_get_arch_info(binary);

#ifdef DEBUG
    //printf("Debug: archi : %d\n", arch->bits_per_address);
    printf("Debug: bfd_get_mach(binary) : %ld\n", bfd_get_mach(binary));
#endif

    return bfd_get_mach(binary) == 8;
}

static bool is_executable(bfd *binary) {
// verify if the binary is directly executable
#ifdef DEBUG
    printf("Debug: binary->flags & EXEC_P : %d\n", (binary->flags & EXEC_P) != 0);
#endif
    return (binary->flags & EXEC_P) != 0;
}

bool verify_binary(bfd *binary) {
#ifdef DEBUG
    printf("Debug: binary = %p\n", binary);
#endif
    // the target contains informations about the analysed binary file
    return is_ELF(binary) && is_64bit(binary) && is_executable(binary);
}
