#include <argp.h>
#include <bfd.h>
#include <err.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "argparser.h"
// Defining the argument structure we will use.

// By default, all options are mandatory
struct argp_option opts[] = {
    {"file", 'f', "FILE", 0, "The input elf file to analyze", 0},
    {"to-inject", 'i', "FILE", 0, "The bin file that contains machine code to be injected", 0},
    {"section-name", 's', "STR", 0, "The name of the newly created section", 0},
    {"base-addr", 'a', "UINT", 0, "The base address of the injected code", 0},
    {"modify-entry", 'b', "[1|0]", 0, "A Boolean that indicates whether the entry function should be modified or not", 0},
    {"dyn-func", 'd', "DYN_FUNC_NAME", 0, "The name of a shared library function which the code will be hooked by this binary and replaced by the injected one", 0},
    {0}
};

error_t parse_opt(int k, char *arg, struct argp_state *state) {
    // Take the current parsed argument
    struct arguments *argstruct = state->input;
    switch (k) {
        case 'f': {
            argstruct->input_file = arg;
            break;
        }
        case 'i': {
            argstruct->machine_code_file = arg;
            break;
        }
        case 's': {
            argstruct->new_section = arg;
            break;
        }
        case 'a': {
            argstruct->addr = arg;
            break;
        }
        case 'b': {
            argstruct->mef = arg;
            break;
        }
        case 'd': {
            argstruct->func_to_replace = arg;
            break;
        }
        case 'h': {
            argp_state_help(state, stdout, ARGP_HELP_PRE_DOC | ARGP_HELP_LONG);
            break;
        }
        case ARGP_KEY_ARG:
            argp_usage(state);
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

struct argp argp = {opts, parse_opt, 0, "This program will inject some extra code into \
'date' binary file.\nWith -m 1 you specify the injected code to be the entrypoints of the victim's program"
" (you need in your code to specify a jump instruction to go back to the original execution if you don't want a segfault)."\
"\nWith -m 0 and -d 'func_name' you specify the injected code to hook the shared library function 'func_name' and replace it by your injected code.", 0, 0, 0};
