#ifndef _MMS_BPF_H_INCLUDED_
#define _MMS_BPF_H_INCLUDED_

#include <stdint.h>
#include <string.h>
#include <linux/bpf.h>

typedef struct {
    char                *name;
    int                  offset;
} mms_bpf_reloc_t;

typedef struct {
    char                *license;
    enum bpf_prog_type   type;
    struct bpf_insn     *ins;
    size_t               nins;
    mms_bpf_reloc_t     *relocs;
    size_t               nrelocs;
} mms_bpf_program_t;


void mms_bpf_program_link(mms_bpf_program_t *program, const char *symbol, int fd);
int mms_bpf_load_program(mms_bpf_program_t *program);

int mms_bpf_map_create(enum bpf_map_type type, int key_size, int value_size, int max_entries, uint32_t map_flags);
int mms_bpf_map_update(int fd, const void *key, const void *value, uint64_t flags);
int mms_bpf_map_delete(int fd, const void *key);
int mms_bpf_map_lookup(int fd, const void *key, void *value);


uint64_t mms_bpf_socket_key(int fd);
int mms_bpf_attach_id(int fd, unsigned char* id);

#endif /* _NGX_BPF_H_INCLUDED_ */