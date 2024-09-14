#pragma once

#define ELF_ALIGN          4096
#define SIZE_BUF           32
#define SECTION_TO_REPLACE ".note.ABI-tag"
#define SH_DYNSTR ".dynstr"
#define SH_DYNAMIC ".dynamic"
#define SH_GOTPLT ".got.plt"
#define SH_DYNTAB ".dynsym"
#define SH_RELAPLT ".rela.plt"

int find_pt_note_index(void *);
size_t append_code(char *, char *);
int overwrite_section_hdr(void *, off_t, char *, uint64_t, size_t);
int sort_section_hdr(void *, unsigned int);
void overwrite_program_hdr(void *, int, size_t, size_t, int64_t);
void modify_entry_point(void *, int64_t);
int replace_in_got(void *, uint64_t, char *);
