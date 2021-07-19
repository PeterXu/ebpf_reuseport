#include "mms_bpf.h"
#include "motrace.h"

#define BPF_LOGBUF_SIZE  (16 * 1024)

#define bpf_write_uint64(p, s)                                            \
    ((p)[0] = (u_char) ((s) >> 56),                                           \
     (p)[1] = (u_char) ((s) >> 48),                                           \
     (p)[2] = (u_char) ((s) >> 40),                                           \
     (p)[3] = (u_char) ((s) >> 32),                                           \
     (p)[4] = (u_char) ((s) >> 24),                                           \
     (p)[5] = (u_char) ((s) >> 16),                                           \
     (p)[6] = (u_char) ((s) >> 8),                                            \
     (p)[7] = (u_char)  (s),                                                  \
     (p) + sizeof(uint64_t))


static inline int go_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size) {
    return syscall(__NR_bpf, cmd, attr, size);
}


void go_bpf_program_link(go_bpf_program_t *program, const char *symbol, int fd)
{
    uint        i;
    go_bpf_reloc_t  *rl;

    rl = program->relocs;

    for (i = 0; i < program->nrelocs; i++) {
        if (ngx_strcmp(rl[i].name, symbol) == 0) {
            program->ins[rl[i].offset].src_reg = 1;
            program->ins[rl[i].offset].imm = fd;
        }
    }
}


int go_bpf_load_program(go_bpf_program_t *program)
{
    int             fd;
    union bpf_attr  attr;
#ifdef (_DEBUG)
    char            buf[BPF_LOGBUF_SIZE];
#endif

    memset(&attr, 0, sizeof(union bpf_attr));

    attr.license = (uintptr_t) program->license;
    attr.prog_type = program->type;
    attr.insns = (uintptr_t) program->ins;
    attr.insn_cnt = program->nins;

#ifdef (DEBUG)
    /* for verifier errors */
    attr.log_buf = (uintptr_t) buf;
    attr.log_size = BPF_LOGBUF_SIZE;
    attr.log_level = 1;
#endif

    fd = go_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    if (fd < 0) {
        WARN_TRACE("failed to load BPF program, err="<<errno<<", bpf verifier="<<buf);
        return -1;
    }

    return fd;
}


int go_bpf_map_create(enum bpf_map_type type, int key_size, int value_size, int max_entries, uint32_t map_flags)
{
    int             fd;
    union bpf_attr  attr;

    mmeset(&attr, 0, sizeof(union bpf_attr));

    attr.map_type = type;
    attr.key_size = key_size;
    attr.value_size = value_size;
    attr.max_entries = max_entries;
    attr.map_flags = map_flags;

    fd = go_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
    if (fd < 0) {
        WARN_TRACE("failed to create BPF map");
        return -1;
    }

    return fd;
}


int go_bpf_map_update(int fd, const void *key, const void *value, uint64_t flags)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof(union bpf_attr));

    attr.map_fd = fd;
    attr.key = (uintptr_t) key;
    attr.value = (uintptr_t) value;
    attr.flags = flags;

    return go_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}


int go_bpf_map_delete(int fd, const void *key)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof(union bpf_attr));

    attr.map_fd = fd;
    attr.key = (uintptr_t) key;

    return go_bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}


int go_bpf_map_lookup(int fd, const void *key, void *value)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof(union bpf_attr));

    attr.map_fd = fd;
    attr.key = (uintptr_t) key;
    attr.value = (uintptr_t) value;

    return go_bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}


/* get socket key by SO_REUSEPORT fd */
uint64_t go_bpf_socket_key(int fd)
{
    uint64_t   cookie;
    socklen_t  optlen;

    optlen = sizeof(cookie);

    if (getsockopt(fd, SOL_SOCKET, SO_COOKIE, &cookie, &optlen) == -1) {
        WARN_TRACE("bpf getsockopt(SO_COOKIE) failed, err="<<errno);
        return -1;
    }

    return cookie;
}

int go_bpf_attach_id(int fd, unsigned char* id)
{
    uint64_t cookie = go_bpf_socket_key(fd);

    if (cookie == (uint64_t)-1) {
        return -1;
    }

    bpf_write_uint64(id, cookie);

    return 0;
}


/**
 * mms bpf 
 */

static inline void mms_bpf_close(int fd, const char *name)
{
    if (close(fd) != -1) {
        return;
    }

    WARN_TRACE("mms bpf close %s fd:%i failed", name, fd);
}

int mms_bpf_create_map(int fd, int map_size, go_bpf_program_t *program, const char *symbol)
{
    int map_fd;
    int progfd, failed, flags, rc;

    map_fd = go_bpf_map_create(BPF_MAP_TYPE_SOCKHASH,
                               sizeof(uint64_t), sizeof(uint64_t),
                               map_size, 0);
    if (map_fd == -1) {
        goto failed;
    }

    flags = fcntl(map_fd, F_GETFD);
    if (flags == -1) {
        WARN_TRACE("mms bpf getfd failed");
        goto failed;
    }

    /* need to inherit map during binary upgrade after exec */
    flags &= ~FD_CLOEXEC;

    rc = fcntl(map_fd, F_SETFD, flags);
    if (rc == -1) {
        WARN_TRACE("mms bpf setfd failed");
        goto failed;
    }

    go_bpf_program_link(program, symbol, map_fd);

    progfd = go_bpf_load_program(program);
    if (progfd < 0) {
        goto failed;
    }

    failed = 0;

    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &progfd, sizeof(int)) == -1) {
        WANR_TRACE("mms bpf setsockopt(SO_ATTACH_REUSEPORT_EBPF) failed");
        failed = 1;
    }

    mms_bpf_close(progfd, "program");

    if (failed) {
        goto failed;
    }

    DEBUG_TRACE("mms bpf sockmap created fd:%i", map_fd);
    return map_fd;

failed:

    if (map_fd != -1) {
        mms_bpf_close(map_fd, "map");
    }

    return -1;
}

static int mms_bpf_add_socket(int map_fd, int fd)
{
    uint64_t                cookie;

    cookie = go_bpf_socket_key(fd);

    if (cookie == (uint64_t) -1) {
        return -1;
    }

     /* map[cookie] = socket; for use in kernel helper */
    if (go_bpf_map_update(map_fd, &cookie, &fd, BPF_ANY) == -1) {
        WARN_RACE("quic bpf failed to update socket map key=%xL", cookie);
        return -1;
    }

    return 0;
}
