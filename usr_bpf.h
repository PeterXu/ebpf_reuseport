#ifndef _BPFTOOLS_H_INCLUDED_
#define _BPFTOOLS_H_INCLUDED_

#include <stdint.h>
#include <string.h>
#include <linux/bpf.h>

/**
 * usr bpf structure
 */
typedef struct {
    char                *name;
    int                  offset;
} usr_bpf_reloc_t;

typedef struct {
    char                *license;
    enum bpf_prog_type   type;

    struct bpf_insn     *ins;
    size_t               nins;

    usr_bpf_reloc_t     *relocs;
    size_t               nrelocs;
} usr_bpf_program_t;


uint64_t go_get_socket_cookie(int fd);

int go_bpf_reuseport_init(int fd, int map_size, usr_bpf_program_t *program, const char *symbol);
int go_bpf_add_socket(int map_fd, int fd, uint64_t key);


#endif /* _NGX_BPF_H_INCLUDED_ */
