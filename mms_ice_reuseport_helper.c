#include <errno.h>
#include <linux/string.h>
#include <linux/udp.h>
#include <linux/bpf.h>
/*
 * the bpf_helpers.h is not included into linux-headers, only available
 * with kernel sources in "tools/lib/bpf/bpf_helpers.h" or in libbpf.
 */
#include <bpf/bpf_helpers.h>


#if !defined(SEC)
#define SEC(NAME)  __attribute__((section(NAME), used))
#endif


#if defined(LICENSE_GPL)

/*
 * To see debug:
 *
 *  echo 1 > /sys/kernel/debug/tracing/events/bpf_trace/enable
 *  cat /sys/kernel/debug/tracing/trace_pipe
 *  echo 0 > /sys/kernel/debug/tracing/events/bpf_trace/enable
 */

#define debugmsg(fmt, ...)                                                    \
do {                                                                          \
    char __buf[] = fmt;                                                       \
    bpf_trace_printk(__buf, sizeof(__buf), ##__VA_ARGS__);                    \
} while (0)

#else

#define debugmsg(fmt, ...)

#endif

char _license[] SEC("license") = LICENSE;


/*****************************************************************************/

#define kStunHeaderSize             20              /* stun header size */
#define kStunTransactionIdLength    12
#define kStunMagicCookie            0x2112A442      /* uint32 */

/* stun type */
enum {
    STUN_BINDING_REQUEST = 0x0001,
    STUN_BINDING_INDICATION = 0x0011,
    STUN_BINDING_RESPONSE = 0x0101,
    STUN_BINDING_ERROR_RESPONSE = 0x0111,
};

/* stun attr */
enum {
    STUN_ATTR_USERNAME = 0x0006,
};


#define mms_ice_parse_uin32(p)                                                \
    (((__u32)(p)[0] << 24) |                                                  \
     ((__u32)(p)[1] << 16) |                                                  \
     ((__u32)(p)[2] << 8)  |                                                  \
     ((__u32)(p)[3]))

#define mms_ice_parse_uin16(p)                                                \
    (((__u16)(p)[0] << 8)  |                                                  \
     ((__u16)(p)[1]))


/*
 * actual map object is created by the "bpf" system call,
 * all pointers to this variable are replaced by the bpf loader
 */
struct bpf_map_def SEC("maps") mms_ice_sockmap;


SEC(PROGNAME)
int mms_ice_select_socket_by_username(struct sk_reuseport_md *ctx)
{
    int             rc;
    __u64           key;
    unsigned char  *start, *end, *data;
    size_t  len, offset;
    __u16   pkt_len, pkt_type;
    __u32   pkt_magic;

    start = ctx->data;
    end = (unsigned char *) ctx->data_end;

    if (ctx->ip_protocol == IPPROTO_UDP) {
        data = start + sizeof(struct udphdr); /* data at UDP header */
    } else if (ctx->ip_protocol == IPPROTO_TCP) {
        data = start + sizeof(struct tcphdr); /* data at TCP header */
    } else {
        debugmsg("unsupported ip protocol: %u", ctx->ip_protocol);
        goto failed;
    }

    len = end - data;

    if (len < kStunHeaderSize) {
        debugmsg("not stun packet, size: %ld", len);
        goto failed;
    }

    /* stun type: 0-2 */
    pkt_type = mms_ice_parse_uin16(data);
    if ((pkt_type & 0x8000) || ((pkt_type>>8) > 1)) {
        debugmsg("not sun packet, invalid type: %u", pkt_type);
        goto failed;
    }

    /* stun body len: 2-4 */
    pkt_len = mms_ice_parse_uin16(data + 2);
    if (pkt_len & 0x0003) {
        debugmsg("not sun packet, invalid len: %u", pkt_len);
        goto failed;
    }

    /* stun magic code: 4-8 */
    pkt_magic = mms_ice_parse_uin32(data + 4);
    if (pkt_magic != kStunMagicCookie) {
        debugmsg("not stun packet, invalid magic: %x", pkt_magic);
        goto failed;
    }

    /* stun transaction id: 8-20 */
    /* skip it */


    /* check stun body len */
    offset = kStunHeaderSize;
    if ((pkt_len + offset) != len) {
        debugmsg("cannot read %u bytes at offset %ld", pkt_len, offset);
        goto failed;
    }

    /* generate key(u64) from stun username */
    key = 0;
    for (; key == 0 && offset + 4 <= len; ) {
        __u16 attr_type = mms_ice_parse_uin16(data + offset);
        __u16 attr_len = mms_ice_parse_uin16(data + offset + 2);
        offset += 4;

        switch (attr_type) {
        case STUN_ATTR_USERNAME:
            {
                unsigned char *pkey = &key;
                unsigned char *username = data + offset;
                for (__u16 i = 0; i < attr_len; i += 1) {
                    pkey[7 - (i % 8)] ^= username[i];
                }
            }
            break;
        default:
            break;
        }

        int new_len = attr_len;
        int remainder = attr_len % 4;
        if (remainder > 0) {
            int padding = 4 - remainder;
            new_len += padding;
        }
        offset += new_len;
    }

    if (!key) {
        debugmsg("no valid key from stun username");
        goto failed;
    }

    /* select SO_REUSEPORT socket from BPF_MAP_TYPE_REUSEPORT_ARRAY map by key */
    rc = bpf_sk_select_reuseport(ctx, &mms_ice_sockmap, &key, 0);

    switch (rc) {
    case 0:
        debugmsg("mms ice socket selected by key 0x%llx", key);
        return SK_PASS;

    /* kernel returns positive error numbers, errno.h defines positive */
    case -ENOENT:
        debugmsg("mms ice default route for key 0x%llx", key);
        /* let the default reuseport logic decide which socket to choose */
        return SK_PASS;

    default:
        debugmsg("mms ice bpf_sk_select_reuseport err: %d key 0x%llx",
                  rc, key);
        goto failed;
    }

failed:
    /*
     * SK_DROP will generate ICMP, but we may want to process "invalid" packet
     * in userspace to investigate further and finally react properly
     * (maybe ignore, maybe send something in response or close connection)
     */
    return SK_PASS;
}
