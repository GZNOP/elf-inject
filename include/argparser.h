#pragma once

#include <argp.h>
#include <stdbool.h>

extern struct argp_option opts[];
extern struct argp argp;
error_t parse_opt(int, char *, struct argp_state *);

// The structure that will control if the argument had been set

struct arguments
{
    char * input_file;        // the input file (copied 'date' binary)
    char * machine_code_file; // binary file, that contains machine code to be injected
    char * new_section;       // the name of the new section
    char * addr;              // the base address of the newly created section
    char * mef;               // check if the address of the entry points should be modified
    char * func_to_replace;   // the function to replace in the got if mef == 0
};