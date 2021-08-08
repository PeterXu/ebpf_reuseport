#include "usr_bpf.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>


#define USR_BPF_LOGBUF_SIZE  (16 * 1024)

#define usr_strcmp(s1, s2)  strcmp((const char *) s1, (const char *) s2)

#define usr_bpf_write_uint64(p, s)                                            \
    ((p)[0] = (u_char) ((s) >> 56),                                           \
     (p)[1] = (u_char) ((s) >> 48),                                           \
     (p)[2] = (u_char) ((s) >> 40),                                           \
     (p)[3] = (u_char) ((s) >> 32),                                           \
     (p)[4] = (u_char) ((s) >> 24),                                           \
     (p)[5] = (u_char) ((s) >> 16),                                           \
     (p)[6] = (u_char) ((s) >> 8),                                            \
     (p)[7] = (u_char)  (s),                                                  \
     (p) + sizeof(uint64_t))


static inline int usr_bpf_call(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size) {
    return syscall(__NR_bpf, cmd, attr, size);
}



/**
 * usr bpf program link
 */
static void usr_bpf_program_link(usr_bpf_program_t *program, const char *symbol, int fd)
{
    uint        i;
    usr_bpf_reloc_t  *rl;

    rl = program->relocs;

    for (i = 0; i < program->nrelocs; i++) {
        if (usr_strcmp(rl[i].name, symbol) == 0) {
            program->ins[rl[i].offset].src_reg = 1;
            program->ins[rl[i].offset].imm = fd;
        }
    }
}

/**
 * usr bpf prgram load
 */
static int usr_bpf_program_load(usr_bpf_program_t *program)
{
    int             fd;
    union bpf_attr  attr;
#ifdef (_DEBUG)
    char            buf[USR_BPF_LOGBUF_SIZE];
#endif

    memset(&attr, 0, sizeof(union bpf_attr));

    attr.license = (uintptr_t) program->license;
    attr.prog_type = program->type;
    attr.insns = (uintptr_t) program->ins;
    attr.insn_cnt = program->nins;

#ifdef (DEBUG)
    /* for verifier errors */
    attr.log_buf = (uintptr_t) buf;
    attr.log_size = USR_BPF_LOGBUF_SIZE;
    attr.log_level = 1;
#endif

    fd = usr_bpf_call(BPF_PROG_LOAD, &attr, sizeof(attr));
    if (fd < 0) {
        fprintf(stderr, "failed to load BPF program, err=%d, bpf verifier=%s", errno, buf);
        return -1;
    }

    return fd;
}



/**
 * usr bpf map create
 */
static int usr_bpf_map_create(enum bpf_map_type type, int key_size, int value_size, int max_entries, uint32_t map_flags)
{
    int             fd;
    union bpf_attr  attr;

    mmeset(&attr, 0, sizeof(union bpf_attr));

    attr.map_type = type;
    attr.key_size = key_size;
    attr.value_size = value_size;
    attr.max_entries = max_entries;
    attr.map_flags = map_flags;

    fd = usr_bpf_call(BPF_MAP_CREATE, &attr, sizeof(attr));
    if (fd < 0) {
        fprintf(stderr, "failed to create BPF map");
        return -1;
    }

    return fd;
}

/**
 * usr bpf map update
 */
static int usr_bpf_map_update(int fd, const void *key, const void *value, uint64_t flags)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof(union bpf_attr));

    attr.map_fd = fd;
    attr.key = (uintptr_t) key;
    attr.value = (uintptr_t) value;
    attr.flags = flags;

    return usr_bpf_call(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

/**
 * usr bpf map delete
 */
static int usr_bpf_map_delete(int fd, const void *key)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof(union bpf_attr));

    attr.map_fd = fd;
    attr.key = (uintptr_t) key;

    return usr_bpf_call(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

/**
 * usr bpf map lookup
 */
static int usr_bpf_map_lookup(int fd, const void *key, void *value)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof(union bpf_attr));

    attr.map_fd = fd;
    attr.key = (uintptr_t) key;
    attr.value = (uintptr_t) value;

    return usr_bpf_call(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}



/**
 * socket cookie
 */
uint64_t go_get_socket_cookie(int fd)
{
    uint64_t   cookie;
    socklen_t  optlen;

    optlen = sizeof(cookie);

    if (getsockopt(fd, SOL_SOCKET, SO_COOKIE, &cookie, &optlen) == -1) {
        fprintf(stderr, "getsockopt(SO_COOKIE) failed, error=%d", errno);
        return -1;
    }

    return cookie;
}


/**
 * bpf close
 */
static inline void go_bpf_close(int fd, const char *name)
{
    if (close(fd) != -1) {
        return;
    }

    fprintf(stderr, "bpf close %s fd:%i failed", name, fd);
}

/**
 * init bpf-map with program and return bpf-map's fd
 * @param fd: listen fd.
 * @param map_size: bpf-map size
 * @param program: bpf-map program, e.g. "ice_reuseport_helper"
 * @param symbol: bpf-map-def name, e.g. "ice_sockmap"
 * @return map-fd
 */
int go_bpf_reuseport_init(int fd, int map_size, usr_bpf_program_t *program, const char *symbol)
{
    int map_fd;
    int progfd, failed, flags, rc;

    map_fd = usr_bpf_map_create(BPF_MAP_TYPE_SOCKHASH,
                               sizeof(uint64_t), sizeof(uint64_t),
                               map_size, 0);
    if (map_fd == -1) {
        goto failed;
    }

    flags = fcntl(map_fd, F_GETFD);
    if (flags == -1) {
        fprintf(stderr, "bpf getfd failed");
        goto failed;
    }

    /* need to inherit map during binary upgrade after exec */
    flags &= ~FD_CLOEXEC;

    rc = fcntl(map_fd, F_SETFD, flags);
    if (rc == -1) {
        fprintf(stderr, "bpf setfd failed");
        goto failed;
    }

    usr_bpf_program_link(program, symbol, map_fd);

    progfd = usr_bpf_program_load(program);
    if (progfd < 0) {
        goto failed;
    }

    failed = 0;

    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &progfd, sizeof(int)) == -1) {
        fprintf(stderr, "bpf setsockopt(SO_ATTACH_REUSEPORT_EBPF) failed");
        failed = 1;
    }

    go_bpf_close(progfd, "program");

    if (failed) {
        goto failed;
    }

    fprintf(stderr, "bpf sockmap created fd:%i", map_fd);
    return map_fd;

failed:

    if (map_fd != -1) {
        go_bpf_close(map_fd, "map");
    }

    return -1;
}

/**
 * add fd to map with key
 * @param map_fd: bpf-map fd
 * @param fd: listen fd
 * @param key: key for listen fd
 */
int go_bpf_add_socket(int map_fd, int fd, uint64_t key)
{
    /* map[key] = socket; for use in kernel helper */
    if (usr_bpf_map_update(map_fd, &key, &fd, BPF_ANY) == -1) {
        fprintf(stderr, "bpf failed to update socket map key=%xL", key);
        return -1;
    }

    return 0;
}
