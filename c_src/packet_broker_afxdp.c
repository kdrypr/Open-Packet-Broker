/*
 * Packet Broker — AF_XDP edition (skeleton)
 *
 * Kernel-bypass data plane using AF_XDP sockets with zero-copy on
 * driver-supported NICs (i40e, igc, ice, mlx5 etc. on Linux >= 5.4).
 * Maintains the same rules.conf format as the libpcap variant.
 *
 * Build:
 *   gcc -O2 -o packet_broker_afxdp packet_broker_afxdp.c \
 *       $(pkg-config --cflags --libs libxdp libbpf libelf) -lpthread
 *
 * Run (root + CAP_NET_ADMIN + CAP_SYS_ADMIN required):
 *   ./packet_broker_afxdp
 *
 * NOTE: This is a feature-incomplete skeleton. Filter matching,
 * VLAN manipulation, mirror/LB/dedup/throttle are placeholders that
 * mirror the libpcap variant's structure; they will be ported in
 * subsequent commits to reach parity.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <strings.h>
#include <ifaddrs.h>
#include <dirent.h>

#include "bpf_helpers.h"   /* opaque cBPF compile/match — avoids pcap/linux header collision */

#include <xdp/xsk.h>
#include <xdp/libxdp.h>
#include <bpf/libbpf.h>

/* ── Constants ─────────────────────────────────────────────────────────── */

#define MAX_RULES       256
#define MAX_INTERFACES  48
#define MAX_XSKS        128   /* covers up to MAX_INTERFACES × MAX_QUEUES_PER_IFACE */
#define MAX_QUEUES_PER_IFACE  8
#define FIELD_LEN       64
#define PB_BPF_LEN      256
#define LINE_LEN        1024

#define ETH_HDR_MIN  14   /* dst(6) + src(6) + ethertype(2) */
#define VLAN_HDR_MIN 18   /* + 802.1Q TCI(2) + inner type(2) */

#define RULE_FILE       "rules.conf"
#define DEDUP_CONF_FILE "dedup.conf"
#define DPI_CONF_FILE   "dpi.conf"
#define LOG_FILE        "packet_broker.log"
#define STATS_FILE      "packet_broker_afxdp.stats.json"
#define PID_FILE        "packet_broker.pid"
#define STATUS_FILE     "packet_broker.status"

#define DEDUP_TABLE_SIZE 65536
#define DPI_STATS_SIZE   64

#define FRAME_SIZE      XSK_UMEM__DEFAULT_FRAME_SIZE      /* 4096 */
#define NUM_FRAMES      8192                              /* 32 MB UMEM, shared */
#define RX_BATCH_SIZE   64
#define TX_BATCH_SIZE   64
#define FQ_REFILL_LO    256                               /* refill fq when below */
#define FQ_REFILL_HI    1024                              /* up to this many */
#define INVALID_UMEM_FRAME UINT64_MAX

#define STATS_INTERVAL  5

/* ── VLAN actions (mirrors libpcap variant) ────────────────────────────── */

enum vlan_action {
    VLAN_NONE   = 0,
    VLAN_ADD    = 1,
    VLAN_REMOVE = 2,
    VLAN_CHANGE = 3,
};

/* ── Rule structure (extended; mirrors libpcap variant for parity) ─────── */

typedef struct {
    /* Core fields (legacy 8-field format) */
    char     iface_in [FIELD_LEN];
    char     tcp_flags[FIELD_LEN];
    int      dest_port;
    char     protocol[FIELD_LEN];        /* "TCP" / "UDP" / "ICMP" / "0" */
    int      vlan_id;                    /* match VLAN; 0 = any */
    char     string_match[FIELD_LEN];
    int      exclude;                    /* 1 = invert */
    char     iface_out[FIELD_LEN];

    /* Extended */
    int      enabled;
    int      priority;
    int      vlan_action;                /* enum vlan_action */
    int      vlan_new_id;
    int      truncate;                   /* byte cap; 0 = full */

    /* IP filter (CIDR — network byte order) */
    uint32_t src_ip,  src_mask;
    uint32_t dst_ip,  dst_mask;

    /* MAC filter */
    uint8_t  src_mac[6];
    uint8_t  dst_mac[6];
    int      has_src_mac;
    int      has_dst_mac;

    /* BPF (still TODO in AF_XDP path — placeholder kept for parity) */
    char     bpf_filter[PB_BPF_LEN];

    /* Throttling token bucket */
    uint64_t rate_limit_bps;             /* derived from Mbps form-input */
    uint64_t rate_limit_pps;
    uint64_t tokens_bytes;
    uint64_t tokens_pkts;
    struct timespec last_refill;

    /* Mirror extras + dedup (mirror_ports CSV; dedup_key 0=off) */
    char     mirror_ports[FIELD_LEN];
    int      dedup_key;

    /* Cached output interface index — resolved at load time */
    int      ifindex_out;

    /* Counters */
    uint64_t drop_count;
    uint64_t match_count;

    /* Compiled cBPF program — opaque handle from bpf_helpers (libpcap-backed) */
    void              *bpf_handle;
} rule_t;

/* ── Shared UMEM + per-XSK rings ───────────────────────────────────────── */

/* One UMEM buffer is shared across all XSKs. Each socket has its own fq/cq.
 * Frames are interchangeable across sockets — that lets us do true zero-copy
 * forwarding: an RX'd frame on XSK-A can be submitted to XSK-B's TX ring
 * without any memcpy. (Manipulated packets — VLAN add/remove/change — still
 * allocate a fresh frame and copy modified bytes.) */
typedef struct shared_umem {
    void                       *buffer;                    /* mmap'd region */
    struct xsk_umem            *umem;

    /* Global free pool — protected by lock. Any socket may pull/push. */
    uint64_t                    free[NUM_FRAMES];
    uint32_t                    free_n;
    pthread_mutex_t             lock;
} shared_umem_t;

typedef struct xsk_info {
    struct xsk_socket          *xsk;
    struct xsk_ring_cons        rx;
    struct xsk_ring_prod        tx;
    struct xsk_ring_prod        fq;                        /* per-socket fill */
    struct xsk_ring_cons        cq;                        /* per-socket comp */
    int                         ifindex;
    char                        ifname[IF_NAMESIZE];
    uint32_t                    queue_id;

    /* Counters */
    uint64_t                    rx_packets;
    uint64_t                    rx_bytes;
    uint64_t                    tx_packets;
    uint64_t                    tx_bytes;
    uint64_t                    rx_dropped;
    uint64_t                    tx_dropped;
} xsk_info_t;

/* ── Globals ───────────────────────────────────────────────────────────── */

static volatile sig_atomic_t   g_running = 1;
static int                     g_allow_mgmt = 0;     /* --allow-mgmt overrides guard */
static rule_t                  g_rules[MAX_RULES];
static int                     g_num_rules = 0;
static time_t                  g_rules_mtime = 0;
static xsk_info_t             *g_xsks[MAX_XSKS];
static int                     g_num_xsks = 0;
static pthread_mutex_t         g_rules_lock = PTHREAD_MUTEX_INITIALIZER;
static FILE                   *g_logf = NULL;
static shared_umem_t           g_umem;                    /* single global UMEM */

/* ── Dedup state (CRC32 ring; mirror libpcap variant) ──────────────────── */
typedef struct {
    uint32_t        hash;
    struct timespec seen;
} dedup_entry_t;
static dedup_entry_t           g_dedup_table[DEDUP_TABLE_SIZE];
static int                     g_dedup_enabled = 0;
static int                     g_dedup_window_us = 100000;  /* 100 ms default */
static int                     g_dedup_hash_bytes = 128;
static pthread_mutex_t         g_dedup_lock = PTHREAD_MUTEX_INITIALIZER;

/* ── DPI state (L7 detection + dpi.conf actions) ───────────────────────── */
typedef struct {
    char     proto[32];
    char     action[16];
    char     output[FIELD_LEN];
} dpi_rule_t;
typedef struct {
    char     proto[32];
    uint64_t count;
    uint64_t bytes;
} dpi_stat_t;
static dpi_rule_t              g_dpi_rules[DPI_STATS_SIZE];
static int                     g_dpi_rule_count = 0;
static dpi_stat_t              g_dpi_stats[DPI_STATS_SIZE];
static int                     g_dpi_stat_count = 0;
static pthread_mutex_t         g_dpi_lock = PTHREAD_MUTEX_INITIALIZER;

/* ── Logging ───────────────────────────────────────────────────────────── */

static void plog(const char *level, const char *fmt, ...) {
    if (!g_logf) g_logf = fopen(LOG_FILE, "a");
    if (!g_logf) return;
    time_t now = time(NULL);
    struct tm tm; localtime_r(&now, &tm);
    char ts[32]; strftime(ts, sizeof ts, "%Y/%m/%d %H:%M:%S", &tm);
    fprintf(g_logf, "%s [%s] ", ts, level);
    va_list ap; va_start(ap, fmt);
    vfprintf(g_logf, fmt, ap);
    va_end(ap);
    fputc('\n', g_logf);
    fflush(g_logf);
}

/* ── Signal handling (mirrors libpcap variant) ─────────────────────────── */

static void handle_signal(int sig) {
    (void)sig;
    g_running = 0;
}

/* ── Mgmt-iface guard ──────────────────────────────────────────────────── */

/* Returns 1 if iface has any IPv4 address assigned (= likely management). */
static int iface_has_ipv4(const char *name) {
    struct ifaddrs *ifap = NULL, *ifa;
    if (getifaddrs(&ifap) != 0) return 0;
    int has = 0;
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name || !ifa->ifa_addr) continue;
        if (strcmp(ifa->ifa_name, name) != 0) continue;
        if (ifa->ifa_addr->sa_family == AF_INET) { has = 1; break; }
    }
    freeifaddrs(ifap);
    return has;
}

/* Returns 1 if iface owns the system default route (4 or 6). */
static int iface_is_default_route(const char *name) {
    FILE *f = fopen("/proc/net/route", "r");
    if (!f) return 0;
    char line[512];
    int found = 0;
    /* skip header */
    if (!fgets(line, sizeof line, f)) { fclose(f); return 0; }
    while (fgets(line, sizeof line, f)) {
        char iface[IF_NAMESIZE]; unsigned long dest;
        if (sscanf(line, "%15s %lx", iface, &dest) == 2) {
            if (dest == 0UL && strcmp(iface, name) == 0) { found = 1; break; }
        }
    }
    fclose(f);
    return found;
}

/* Returns 1 if attaching XDP to this iface would likely lock the operator out. */
static int iface_is_management(const char *name) {
    return iface_is_default_route(name) || iface_has_ipv4(name);
}

/* ── Global UMEM free pool (mutex-protected) ───────────────────────────── */

static uint64_t global_alloc(void) {
    uint64_t a = INVALID_UMEM_FRAME;
    pthread_mutex_lock(&g_umem.lock);
    if (g_umem.free_n > 0) a = g_umem.free[--g_umem.free_n];
    pthread_mutex_unlock(&g_umem.lock);
    return a;
}

static uint32_t global_alloc_batch(uint64_t *out, uint32_t n) {
    uint32_t got = 0;
    pthread_mutex_lock(&g_umem.lock);
    while (got < n && g_umem.free_n > 0) out[got++] = g_umem.free[--g_umem.free_n];
    pthread_mutex_unlock(&g_umem.lock);
    return got;
}

static void global_free(uint64_t addr) {
    pthread_mutex_lock(&g_umem.lock);
    if (g_umem.free_n < NUM_FRAMES) g_umem.free[g_umem.free_n++] = addr;
    pthread_mutex_unlock(&g_umem.lock);
}

/* ── Shared UMEM init ──────────────────────────────────────────────────── */

/* Sized to hold the primary fq/cq returned from xsk_umem__create; these
 * become the fq/cq of the FIRST socket we open via xsk_socket__create. */
static struct xsk_ring_prod g_umem_primary_fq;
static struct xsk_ring_cons g_umem_primary_cq;

static int umem_global_init(void) {
    size_t bytes = (size_t)NUM_FRAMES * FRAME_SIZE;
    g_umem.buffer = mmap(NULL, bytes,
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_umem.buffer == MAP_FAILED) {
        plog("ERROR", "mmap shared UMEM (%zu B) failed: %s", bytes, strerror(errno));
        return -1;
    }

    struct xsk_umem_config cfg = {
        .fill_size      = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .comp_size      = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .frame_size     = FRAME_SIZE,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
        .flags          = 0,
    };
    if (xsk_umem__create(&g_umem.umem, g_umem.buffer, bytes,
                         &g_umem_primary_fq, &g_umem_primary_cq, &cfg) != 0) {
        plog("ERROR", "xsk_umem__create failed: %s", strerror(errno));
        munmap(g_umem.buffer, bytes);
        return -1;
    }

    pthread_mutex_init(&g_umem.lock, NULL);
    for (uint32_t i = 0; i < NUM_FRAMES; i++)
        g_umem.free[i] = (uint64_t)i * FRAME_SIZE;
    g_umem.free_n = NUM_FRAMES;

    plog("INFO", "Shared UMEM ready: %u frames × %u B (%.1f MB)",
         NUM_FRAMES, FRAME_SIZE, (double)bytes / (1024 * 1024));
    return 0;
}

/* ── XSK socket setup (shared UMEM) ────────────────────────────────────── */

static xsk_info_t *xsk_open(const char *ifname, uint32_t queue_id, int is_first) {
    xsk_info_t *x = calloc(1, sizeof *x);
    if (!x) return NULL;
    strncpy(x->ifname, ifname, IF_NAMESIZE - 1);
    x->queue_id = queue_id;
    x->ifindex  = if_nametoindex(ifname);
    if (x->ifindex == 0) {
        plog("ERROR", "if_nametoindex(%s) failed", ifname);
        free(x);
        return NULL;
    }

    struct xsk_socket_config cfg = {
        .rx_size      = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size      = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .libbpf_flags = 0,
        .xdp_flags    = XDP_FLAGS_DRV_MODE,
        .bind_flags   = XDP_USE_NEED_WAKEUP | XDP_ZEROCOPY,
    };

    int err;
    if (is_first) {
        /* First socket: claims the UMEM's primary fq/cq. */
        err = xsk_socket__create(&x->xsk, ifname, queue_id, g_umem.umem,
                                 &x->rx, &x->tx, &cfg);
        if (!err) { x->fq = g_umem_primary_fq; x->cq = g_umem_primary_cq; }
    } else {
        /* Subsequent sockets share the UMEM but bring fresh fq/cq. */
        err = xsk_socket__create_shared(&x->xsk, ifname, queue_id, g_umem.umem,
                                        &x->rx, &x->tx, &x->fq, &x->cq, &cfg);
    }

    if (err) {
        plog("WARN", "%s q%u zero-copy/drv-mode failed (%s), retrying copy + SKB(generic) mode",
             ifname, queue_id, strerror(-err));
        /* Force GENERIC (SKB) XDP + copy. xdp_flags=0 lets libbpf try DRV first and
         * hard-fail on drivers without native XDP (e.g. vmxnet3 and most virtual
         * NICs); XDP_FLAGS_SKB_MODE is guaranteed to attach on ANY interface, so
         * AF_XDP works everywhere (no zero-copy gain, but it captures). This is the
         * "make AF_XDP the default without waiting for a native NIC" fix. */
        cfg.bind_flags = XDP_USE_NEED_WAKEUP | XDP_COPY;
        cfg.xdp_flags  = XDP_FLAGS_SKB_MODE;
        if (is_first) {
            err = xsk_socket__create(&x->xsk, ifname, queue_id, g_umem.umem,
                                     &x->rx, &x->tx, &cfg);
            if (!err) { x->fq = g_umem_primary_fq; x->cq = g_umem_primary_cq; }
        } else {
            err = xsk_socket__create_shared(&x->xsk, ifname, queue_id, g_umem.umem,
                                            &x->rx, &x->tx, &x->fq, &x->cq, &cfg);
        }
    }
    if (err) {
        plog("ERROR", "%s q%u: xsk_socket__create failed: %s",
             ifname, queue_id, strerror(-err));
        free(x);
        return NULL;
    }

    /* Prime this socket's fill ring */
    uint32_t want = XSK_RING_PROD__DEFAULT_NUM_DESCS / 2;
    uint64_t addrs[XSK_RING_PROD__DEFAULT_NUM_DESCS / 2];
    uint32_t got = global_alloc_batch(addrs, want);
    uint32_t idx;
    if (got > 0 && xsk_ring_prod__reserve(&x->fq, got, &idx) == got) {
        for (uint32_t i = 0; i < got; i++)
            *xsk_ring_prod__fill_addr(&x->fq, idx + i) = addrs[i];
        xsk_ring_prod__submit(&x->fq, got);
    } else {
        /* Couldn't reserve the fill slots — return the frames to the pool
         * instead of leaking them. */
        for (uint32_t i = 0; i < got; i++)
            global_free(addrs[i]);
    }

    plog("INFO", "XSK opened: %s queue %u (mode=%s)",
         ifname, queue_id,
         (cfg.bind_flags & XDP_ZEROCOPY) ? "zerocopy" : "copy");
    return x;
}

/* ── Parsing helpers (ported from libpcap variant for parity) ──────────── */

static void trim(char *s) {
    char *p = s;
    while (*p == ' ' || *p == '\t') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    int len = (int)strlen(s);
    while (len > 0 && (s[len-1] == ' ' || s[len-1] == '\t' ||
                       s[len-1] == '\r' || s[len-1] == '\n'))
        s[--len] = '\0';
}

/* Parse "192.168.1.0/24" into network-order ip + mask. "0" or empty → 0/0. */
static int parse_cidr(const char *s, uint32_t *ip, uint32_t *mask) {
    if (!s || !*s || strcmp(s, "0") == 0) {
        *ip = 0; *mask = 0;
        return 0;
    }
    char buf[64];
    strncpy(buf, s, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char *slash = strchr(buf, '/');
    int prefix = 32;
    if (slash) { *slash = '\0'; prefix = atoi(slash + 1); }
    if (prefix < 0)  prefix = 0;
    if (prefix > 32) prefix = 32;
    struct in_addr a;
    if (inet_aton(buf, &a) == 0) { *ip = 0; *mask = 0; return -1; }
    *ip   = a.s_addr;
    *mask = (prefix == 0) ? 0 : htonl(~((1u << (32 - prefix)) - 1));
    return 0;
}

/* Parse "AA:BB:CC:DD:EE:FF" — returns 1 on success, 0 otherwise. */
static int parse_mac(const char *s, uint8_t mac[6]) {
    if (!s || !*s || strcmp(s, "0") == 0) return 0;
    unsigned int m[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6)
        return 0;
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)m[i];
    return 1;
}

static int parse_vlan_action(const char *s) {
    if (!s || !*s || strcmp(s, "none") == 0 || strcmp(s, "0") == 0) return VLAN_NONE;
    if (strcmp(s, "add")    == 0) return VLAN_ADD;
    if (strcmp(s, "remove") == 0) return VLAN_REMOVE;
    if (strcmp(s, "change") == 0) return VLAN_CHANGE;
    return VLAN_NONE;
}

/* ── Rule loading from rules.conf ──────────────────────────────────────── */

static int rules_load(void) {
    FILE *f = fopen(RULE_FILE, "r");
    if (!f) {
        plog("WARN", "Cannot open %s — running with zero rules", RULE_FILE);
        pthread_mutex_lock(&g_rules_lock);
        g_num_rules = 0;
        pthread_mutex_unlock(&g_rules_lock);
        return -1;
    }

    rule_t  staging[MAX_RULES];
    int     count = 0;
    char    line[LINE_LEN];

    while (fgets(line, sizeof line, f) && count < MAX_RULES) {
        trim(line);
        if (line[0] == '\0' || line[0] == '#') continue;

        char *fields[22];
        int nf = 0;
        char *tok = strtok(line, ",");
        while (tok && nf < 22) {
            fields[nf] = tok;
            trim(fields[nf]);
            nf++;
            tok = strtok(NULL, ",");
        }
        if (nf < 8) continue;

        rule_t *r = &staging[count];
        memset(r, 0, sizeof *r);

        /* Core 8 fields */
        strncpy(r->iface_in,     fields[0], FIELD_LEN - 1);
        strncpy(r->tcp_flags,    fields[1], FIELD_LEN - 1);
        r->dest_port = atoi(fields[2]);
        strncpy(r->protocol,     fields[3], FIELD_LEN - 1);
        r->vlan_id   = atoi(fields[4]);
        strncpy(r->string_match, fields[5], FIELD_LEN - 1);
        r->exclude   = atoi(fields[6]);
        strncpy(r->iface_out,    fields[7], FIELD_LEN - 1);

        /* Extended fields with defaults */
        r->enabled     = nf > 8  ? atoi(fields[8])                  : 1;
        r->priority    = nf > 9  ? atoi(fields[9])                  : count;
        r->vlan_action = nf > 10 ? parse_vlan_action(fields[10])    : VLAN_NONE;
        r->vlan_new_id = nf > 11 ? atoi(fields[11])                 : 0;
        r->truncate    = nf > 12 ? atoi(fields[12])                 : 0;
        if (nf > 13) parse_cidr(fields[13], &r->src_ip, &r->src_mask);
        if (nf > 14) parse_cidr(fields[14], &r->dst_ip, &r->dst_mask);
        if (nf > 15) r->has_src_mac = parse_mac(fields[15], r->src_mac);
        if (nf > 16) r->has_dst_mac = parse_mac(fields[16], r->dst_mac);
        if (nf > 17) strncpy(r->bpf_filter, fields[17], PB_BPF_LEN - 1);

        /* Compile per-rule cBPF filter (handed off to bpf_helpers wrapper).
         * Empty string or literal "0" both mean "no filter" — match libpcap's
         * CSV placeholder convention so existing rules don't trigger errors. */
        if (r->bpf_filter[0] != '\0' && strcmp(r->bpf_filter, "0") != 0) {
            char err[128] = {0};
            r->bpf_handle = pb_bpf_compile(r->bpf_filter, err, sizeof err);
            if (!r->bpf_handle)
                plog("WARN", "BPF compile failed for '%s' — %s",
                     r->bpf_filter, err[0] ? err : "(no error detail)");
        }
        if (nf > 18) {
            int mbps = atoi(fields[18]);
            r->rate_limit_bps = (uint64_t)mbps * 125000ULL; /* Mbps → B/s */
        }
        if (nf > 19) r->rate_limit_pps = (uint64_t)atoi(fields[19]);
        if (nf > 20) strncpy(r->mirror_ports, fields[20], FIELD_LEN - 1);
        if (nf > 21) r->dedup_key = atoi(fields[21]);

        if (r->rate_limit_bps > 0) r->tokens_bytes = r->rate_limit_bps;
        if (r->rate_limit_pps > 0) r->tokens_pkts  = r->rate_limit_pps;
        clock_gettime(CLOCK_MONOTONIC, &r->last_refill);

        /* Skip disabled / invalid */
        if (!r->enabled)                              continue;
        if (r->iface_in[0] == '\0' || r->iface_out[0] == '\0') continue;

        /* Cache output ifindex (0 if not present yet — match path tolerates) */
        r->ifindex_out = (int)if_nametoindex(r->iface_out);

        count++;
    }
    fclose(f);

    /* Sort by priority (stable insertion-style; small N) */
    for (int i = 0; i < count - 1; i++)
        for (int j = i + 1; j < count; j++)
            if (staging[j].priority < staging[i].priority) {
                rule_t tmp = staging[i];
                staging[i] = staging[j];
                staging[j] = tmp;
            }

    pthread_mutex_lock(&g_rules_lock);
    /* Free previous BPF programs before overwriting */
    for (int i = 0; i < g_num_rules; i++) {
        if (g_rules[i].bpf_handle) {
            pb_bpf_free(g_rules[i].bpf_handle);
            g_rules[i].bpf_handle = NULL;
        }
    }
    memcpy(g_rules, staging, sizeof(rule_t) * count);
    g_num_rules = count;
    pthread_mutex_unlock(&g_rules_lock);

    plog("INFO", "Loaded %d rules from %s", count, RULE_FILE);
    return count;
}

/* Hot-reload: check rules.conf mtime; reload if changed. */
static void rules_check_reload(void) {
    struct stat st;
    if (stat(RULE_FILE, &st) != 0) return;
    if (st.st_mtime == g_rules_mtime) return;
    g_rules_mtime = st.st_mtime;
    plog("INFO", "rules.conf changed, reloading");
    rules_load();
}

/* ── Dedup helpers (ported from libpcap variant) ───────────────────────── */

static uint32_t crc32_calc(const uint8_t *data, int len) {
    uint32_t crc = 0xFFFFFFFF;
    for (int i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
    }
    return ~crc;
}

static int is_duplicate(const uint8_t *pkt, int len) {
    if (!g_dedup_enabled) return 0;
    int hl = len < g_dedup_hash_bytes ? len : g_dedup_hash_bytes;
    uint32_t h = crc32_calc(pkt, hl);
    int idx = h & (DEDUP_TABLE_SIZE - 1);
    struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);

    pthread_mutex_lock(&g_dedup_lock);
    dedup_entry_t *e = &g_dedup_table[idx];
    if (e->hash == h) {
        long us = (now.tv_sec - e->seen.tv_sec) * 1000000L +
                  (now.tv_nsec - e->seen.tv_nsec) / 1000L;
        if (us < g_dedup_window_us) {
            pthread_mutex_unlock(&g_dedup_lock);
            return 1;
        }
    }
    e->hash = h;
    e->seen = now;
    pthread_mutex_unlock(&g_dedup_lock);
    return 0;
}

static void load_dedup_config(void) {
    FILE *f = fopen(DEDUP_CONF_FILE, "r");
    if (!f) { g_dedup_enabled = 0; return; }
    char line[256];
    int any = 0;
    while (fgets(line, sizeof line, f)) {
        char port[FIELD_LEN]; int en, wms, hb;
        if (sscanf(line, "%63[^,],%d,%d,%d", port, &en, &wms, &hb) >= 2 && en) {
            any = 1;
            if (wms > 0) g_dedup_window_us  = wms * 1000;
            if (hb  > 0) g_dedup_hash_bytes = hb;
        }
    }
    fclose(f);
    g_dedup_enabled = any;
    if (any) plog("INFO", "Dedup enabled: window=%dus hash=%dB",
                  g_dedup_window_us, g_dedup_hash_bytes);
}

/* ── DPI: L7 detection + dpi.conf actions (ported) ─────────────────────── */

static void dpi_record(const char *proto, int pkt_len) {
    pthread_mutex_lock(&g_dpi_lock);
    for (int i = 0; i < g_dpi_stat_count; i++) {
        if (strcmp(g_dpi_stats[i].proto, proto) == 0) {
            g_dpi_stats[i].count++;
            g_dpi_stats[i].bytes += pkt_len;
            pthread_mutex_unlock(&g_dpi_lock);
            return;
        }
    }
    if (g_dpi_stat_count < DPI_STATS_SIZE) {
        strncpy(g_dpi_stats[g_dpi_stat_count].proto, proto, 31);
        g_dpi_stats[g_dpi_stat_count].count = 1;
        g_dpi_stats[g_dpi_stat_count].bytes = pkt_len;
        g_dpi_stat_count++;
    }
    pthread_mutex_unlock(&g_dpi_lock);
}

static const char *detect_l7_protocol(const uint8_t *payload, int len,
                                       int ip_proto, int src_port, int dst_port) {
    if (len < 2) return "unknown";
    if ((dst_port == 53 || src_port == 53) && ip_proto == IPPROTO_UDP && len >= 12) return "dns";
    if ((dst_port == 123 || src_port == 123) && ip_proto == IPPROTO_UDP) return "ntp";
    if ((dst_port == 161 || dst_port == 162 || src_port == 161) && ip_proto == IPPROTO_UDP) return "snmp";
    if (dst_port == 3389 || src_port == 3389) return "rdp";

    if ((dst_port == 502 || src_port == 502) && len >= 7 &&
        payload[2] == 0x00 && payload[3] == 0x00) return "modbus";
    if ((dst_port == 20000 || src_port == 20000) && len >= 2 &&
        payload[0] == 0x05 && payload[1] == 0x64) return "dnp3";
    if ((dst_port == 102 || src_port == 102) && len >= 4 &&
        payload[0] == 0x03 && payload[1] == 0x00) return "s7comm";
    if ((dst_port == 44818 || src_port == 44818 || dst_port == 2222 || src_port == 2222) && len >= 4) return "enip";
    if ((dst_port == 47808 || src_port == 47808) && ip_proto == IPPROTO_UDP && len >= 4 &&
        payload[0] == 0x81) return "bacnet";
    if ((dst_port == 4840 || src_port == 4840) && len >= 4) {
        if (memcmp(payload, "OPN", 3) == 0 || memcmp(payload, "HEL", 3) == 0 ||
            memcmp(payload, "ACK", 3) == 0 || memcmp(payload, "MSG", 3) == 0) return "opcua";
    }
    if ((dst_port == 2404 || src_port == 2404) && len >= 2 && payload[0] == 0x68) return "iec104";
    if ((dst_port == 9600 || src_port == 9600) && len >= 4 &&
        (memcmp(payload, "FINS", 4) == 0 || payload[0] == 0x80)) return "fins";
    if ((dst_port == 5094 || src_port == 5094) && len >= 4) return "hartip";

    if (len >= 4) {
        if (memcmp(payload, "GET ", 4) == 0 || memcmp(payload, "POST", 4) == 0 ||
            memcmp(payload, "PUT ", 4) == 0 || memcmp(payload, "HEAD", 4) == 0 ||
            memcmp(payload, "HTTP", 4) == 0 || memcmp(payload, "DELE", 4) == 0 ||
            memcmp(payload, "PATC", 4) == 0 || memcmp(payload, "OPTI", 4) == 0) return "http";
    }
    if (len >= 6 && payload[0] == 0x16 && payload[1] == 0x03 &&
        payload[2] <= 0x04) return "tls";
    if (len >= 4 && memcmp(payload, "SSH-", 4) == 0) return "ssh";
    if (len >= 4) {
        if (memcmp(payload, "220 ", 4) == 0 || memcmp(payload, "EHLO", 4) == 0 ||
            memcmp(payload, "HELO", 4) == 0 || memcmp(payload, "MAIL", 4) == 0) return "smtp";
    }
    if (len >= 4 && (dst_port == 21 || src_port == 21)) {
        if (memcmp(payload, "220-", 4) == 0 || memcmp(payload, "220 ", 4) == 0 ||
            memcmp(payload, "USER", 4) == 0 || memcmp(payload, "PASS", 4) == 0) return "ftp";
    }
    if (len >= 2 && ((payload[0] & 0xF0) == 0x10 || (payload[0] & 0xF0) == 0x20) &&
        (dst_port == 1883 || dst_port == 8883 || src_port == 1883)) return "mqtt";
    if (len >= 7 && (memcmp(payload, "SIP/2.0", 7) == 0 || memcmp(payload, "INVITE ", 7) == 0)) return "sip";
    if (len >= 8 && (dst_port == 445 || src_port == 445)) {
        if (payload[4] == 0xFF && payload[5] == 'S' && payload[6] == 'M' && payload[7] == 'B') return "smb";
        if (payload[4] == 0xFE && payload[5] == 'S' && payload[6] == 'M' && payload[7] == 'B') return "smb";
    }
    if ((dst_port == 389 || dst_port == 636 || src_port == 389) && len >= 2 &&
        payload[0] == 0x30) return "ldap";
    return "unknown";
}

static void load_dpi_config(void) {
    FILE *f = fopen(DPI_CONF_FILE, "r");
    if (!f) {
        pthread_mutex_lock(&g_dpi_lock);
        g_dpi_rule_count = 0;
        pthread_mutex_unlock(&g_dpi_lock);
        return;
    }
    /* Stage parsed rules in a local buffer so the rx hot path never
     * sees a torn read of g_dpi_rules during reload — the previous
     * implementation did strncpy + g_dpi_rule_count++ in place and a
     * concurrent strcmp() in match_rule could see a non-NUL-terminated
     * proto string, triggering an OOB read. */
    dpi_rule_t staging[DPI_STATS_SIZE];
    int count = 0;
    char line[256];
    while (fgets(line, sizeof line, f) && count < DPI_STATS_SIZE) {
        char proto[32], action[16], output[FIELD_LEN];
        if (sscanf(line, "%31[^,],%15[^,],%63s", proto, action, output) >= 2) {
            memset(&staging[count], 0, sizeof(dpi_rule_t));
            strncpy(staging[count].proto,  proto,  31);
            strncpy(staging[count].action, action, 15);
            strncpy(staging[count].output, output, FIELD_LEN - 1);
            count++;
        }
    }
    fclose(f);

    pthread_mutex_lock(&g_dpi_lock);
    memcpy(g_dpi_rules, staging, sizeof(dpi_rule_t) * (size_t)count);
    g_dpi_rule_count = count;
    pthread_mutex_unlock(&g_dpi_lock);

    if (count > 0) plog("INFO", "Loaded %d DPI rules", count);
}

/* Light-weight L7 detector wrapper that also handles eth/IP parsing once
 * per packet, then records stats. Returns the protocol id string. */
static const char *l7_classify(const uint8_t *pkt, int len) {
    if (len < ETH_HDR_MIN) return "unknown";
    int eth_hl = 14;
    uint16_t et;
    memcpy(&et, pkt + 12, 2); et = ntohs(et);
    if (et == ETHERTYPE_VLAN) {
        if (len < VLAN_HDR_MIN) return "unknown";
        eth_hl = 18;
        memcpy(&et, pkt + 16, 2); et = ntohs(et);
    }
    if (et != ETHERTYPE_IP || len < eth_hl + 20) return "unknown";
    const struct ip *iph = (const struct ip *)(pkt + eth_hl);
    int ip_hl = iph->ip_hl * 4;
    /* ip_hl is an attacker-controlled nibble; reject a too-short header or
     * one that overruns the captured bytes (mirrors match_rule). */
    if (ip_hl < 20 || eth_hl + ip_hl > len) return "unknown";
    int sport = 0, dport = 0;
    const uint8_t *l7 = pkt + eth_hl + ip_hl;
    int l7_len = len - eth_hl - ip_hl;
    if (iph->ip_p == IPPROTO_TCP && len >= eth_hl + ip_hl + 20) {
        const struct tcphdr *t = (const struct tcphdr *)(pkt + eth_hl + ip_hl);
        sport = ntohs(t->th_sport); dport = ntohs(t->th_dport);
        int tcp_hl = t->th_off * 4;
        l7     = pkt + eth_hl + ip_hl + tcp_hl;
        l7_len = len - eth_hl - ip_hl - tcp_hl;
    } else if (iph->ip_p == IPPROTO_UDP && len >= eth_hl + ip_hl + 8) {
        const struct udphdr *u = (const struct udphdr *)(pkt + eth_hl + ip_hl);
        sport = ntohs(u->uh_sport); dport = ntohs(u->uh_dport);
        l7     = pkt + eth_hl + ip_hl + 8;
        l7_len = len - eth_hl - ip_hl - 8;
    }
    if (l7_len <= 0) return "unknown";
    return detect_l7_protocol(l7, l7_len, iph->ip_p, sport, dport);
}

/* ── VLAN helpers (mirrors libpcap variant for byte-exact behavior) ──────
 *
 * Every helper bounds-checks `len` before touching the packet. Sub-14-byte
 * runt frames are rejected outright; sub-18 means we treat the frame as
 * untagged. This closes the C1/C3 packet-parsing OOB family of bugs the
 * audit flagged: without these guards, a malicious sub-12-byte frame
 * routed through a VLAN_ADD rule yielded `memcpy(_, _, len-12)` with
 * len-12 ≈ 4 GiB → full OOB read+write, RCE primitive on root daemon.
 * (ETH_HDR_MIN / VLAN_HDR_MIN are defined once near the top of the file.)
 */

static inline int has_vlan_tag(const uint8_t *pkt, int len) {
    if (len < ETH_HDR_MIN) return 0;
    uint16_t et;
    memcpy(&et, pkt + 12, 2);
    return ntohs(et) == ETHERTYPE_VLAN;
}

static inline int get_vlan_id(const uint8_t *pkt, int len) {
    if (len < VLAN_HDR_MIN) return 0;
    uint16_t tci;
    memcpy(&tci, pkt + 14, 2);
    return ntohs(tci) & 0x0FFF;
}

/* Insert 802.1Q tag after src MAC. Returns new length, or unchanged len
 * if the input is shorter than an Ethernet header or the output buffer
 * is too small. */
static int vlan_tag_add(const uint8_t *pkt, int len, int vlan_id,
                        uint8_t *out_buf, int out_buf_size) {
    if (len < ETH_HDR_MIN)         return len;
    if (len + 4 > out_buf_size)    return len;
    memcpy(out_buf, pkt, 12);
    out_buf[12] = 0x81; out_buf[13] = 0x00;
    uint16_t tci = htons((uint16_t)(vlan_id & 0x0FFF));
    memcpy(out_buf + 14, &tci, 2);
    memcpy(out_buf + 16, pkt + 12, (size_t)(len - 12));
    return len + 4;
}

/* Strip 802.1Q tag if present. Untagged or runt frames are copied as-is. */
static int vlan_tag_remove(const uint8_t *pkt, int len,
                           uint8_t *out_buf, int out_buf_size) {
    if (len < ETH_HDR_MIN || len > out_buf_size) return len;
    if (!has_vlan_tag(pkt, len) || len < VLAN_HDR_MIN) {
        memcpy(out_buf, pkt, (size_t)len);
        return len;
    }
    memcpy(out_buf, pkt, 12);
    memcpy(out_buf + 12, pkt + 16, (size_t)(len - 16));
    return len - 4;
}

/* Change VLAN ID (preserves priority). If untagged, behaves like add. */
static int vlan_tag_change(const uint8_t *pkt, int len, int new_vlan_id,
                           uint8_t *out_buf, int out_buf_size) {
    if (len < ETH_HDR_MIN)                            return len;
    if (!has_vlan_tag(pkt, len) || len < VLAN_HDR_MIN)
        return vlan_tag_add(pkt, len, new_vlan_id, out_buf, out_buf_size);
    if (len > out_buf_size) return len;
    memcpy(out_buf, pkt, (size_t)len);
    uint16_t tci;
    memcpy(&tci, out_buf + 14, 2);
    tci = ntohs(tci);
    tci = (tci & 0xF000) | (new_vlan_id & 0x0FFF);
    tci = htons(tci);
    memcpy(out_buf + 14, &tci, 2);
    return len;
}

/* ── Packet matching ───────────────────────────────────────────────────── */

static int match_rule(const rule_t *r, const uint8_t *pkt, int len) {
    /* Reject runt frames before any header walking. */
    if (len < ETH_HDR_MIN) return 0;

    /* cBPF filter (compiled from r->bpf_filter at rules_load time) — applied
     * first because it can short-circuit the rest of the matcher cheaply.
     * SPAN/mirror sources may deliver 802.1Q-tagged frames, and a plain
     * expression like "tcp port 443" can't see through the tag (ethertype sits
     * at offset 16, not 12). Present a de-tagged copy so the operator's filter
     * matches regardless of tagging — the structured fields below already skip
     * the tag. */
    if (r->bpf_handle) {
        const uint8_t *fpkt = pkt;
        int flen = len;
        uint8_t detag[FRAME_SIZE];
        uint16_t et0;
        memcpy(&et0, pkt + 12, 2);
        if (ntohs(et0) == ETHERTYPE_VLAN && len >= VLAN_HDR_MIN) {
            int n = len - 4;
            if (n > (int)sizeof(detag)) n = (int)sizeof(detag);
            memcpy(detag, pkt, 12);
            memcpy(detag + 12, pkt + 16, (size_t)(n - 12));
            fpkt = detag;
            flen = n;
        }
        if (!pb_bpf_match(r->bpf_handle, fpkt, flen)) return 0;
    }

    int eth_hdr_len = 14;
    uint16_t ethertype;
    memcpy(&ethertype, pkt + 12, 2);
    ethertype = ntohs(ethertype);
    if (ethertype == ETHERTYPE_VLAN) {
        if (len < VLAN_HDR_MIN) return 0;
        eth_hdr_len = 18;
        memcpy(&ethertype, pkt + 16, 2);
        ethertype = ntohs(ethertype);
    }

    /* MAC filter */
    if (r->has_dst_mac && memcmp(pkt,     r->dst_mac, 6) != 0) return 0;
    if (r->has_src_mac && memcmp(pkt + 6, r->src_mac, 6) != 0) return 0;

    /* VLAN match */
    if (r->vlan_id != 0) {
        if (!has_vlan_tag(pkt, len))             return 0;
        if (get_vlan_id(pkt, len) != r->vlan_id) return 0;
    }

    /* Non-IP fallthrough */
    if (ethertype != ETHERTYPE_IP) {
        if (r->dest_port != 0) return 0;
        if (r->protocol[0] != '\0' && strcmp(r->protocol, "0") != 0) return 0;
        if (r->src_ip != 0 || r->dst_ip != 0) return 0;
        if (r->tcp_flags[0] != '\0' && strcmp(r->tcp_flags, "0") != 0) return 0;
        return 1;
    }

    if (len < eth_hdr_len + 20) return 0;
    const struct ip *iph = (const struct ip *)(pkt + eth_hdr_len);
    int ip_hdr_len = iph->ip_hl * 4;
    if (ip_hdr_len < 20) return 0;

    if (r->src_ip != 0 &&
        (iph->ip_src.s_addr & r->src_mask) != (r->src_ip & r->src_mask)) return 0;
    if (r->dst_ip != 0 &&
        (iph->ip_dst.s_addr & r->dst_mask) != (r->dst_ip & r->dst_mask)) return 0;

    if (r->protocol[0] != '\0' && strcmp(r->protocol, "0") != 0) {
        if (strcasecmp(r->protocol, "TCP")  == 0 && iph->ip_p != IPPROTO_TCP)  return 0;
        if (strcasecmp(r->protocol, "UDP")  == 0 && iph->ip_p != IPPROTO_UDP)  return 0;
        if (strcasecmp(r->protocol, "ICMP") == 0 && iph->ip_p != IPPROTO_ICMP) return 0;
    }

    if (iph->ip_p == IPPROTO_TCP && len >= eth_hdr_len + ip_hdr_len + 20) {
        const struct tcphdr *tcp =
            (const struct tcphdr *)(pkt + eth_hdr_len + ip_hdr_len);

        if (r->dest_port != 0 && ntohs(tcp->th_dport) != r->dest_port) return 0;

        if (r->tcp_flags[0] != '\0' && strcmp(r->tcp_flags, "0") != 0) {
            uint8_t flags = tcp->th_flags;
            for (const char *f = r->tcp_flags; *f; f++) {
                switch (*f) {
                    case 'S': if (!(flags & TH_SYN))  return 0; break;
                    case 'A': if (!(flags & TH_ACK))  return 0; break;
                    case 'F': if (!(flags & TH_FIN))  return 0; break;
                    case 'R': if (!(flags & TH_RST))  return 0; break;
                    case 'P': if (!(flags & TH_PUSH)) return 0; break;
                    case 'U': if (!(flags & TH_URG))  return 0; break;
                }
            }
        }

        if (r->string_match[0] != '\0' && strcmp(r->string_match, "0") != 0) {
            int tcp_hdr_len  = tcp->th_off * 4;
            int payload_off  = eth_hdr_len + ip_hdr_len + tcp_hdr_len;
            int payload_len  = len - payload_off;
            if (payload_len <= 0) return 0;
            if (!memmem(pkt + payload_off, payload_len,
                        r->string_match, strlen(r->string_match)))
                return 0;
        }
    } else if (iph->ip_p == IPPROTO_UDP && len >= eth_hdr_len + ip_hdr_len + 8) {
        const struct udphdr *udp =
            (const struct udphdr *)(pkt + eth_hdr_len + ip_hdr_len);

        if (r->dest_port != 0 && ntohs(udp->uh_dport) != r->dest_port) return 0;

        if (r->string_match[0] != '\0' && strcmp(r->string_match, "0") != 0) {
            int payload_off  = eth_hdr_len + ip_hdr_len + 8;
            int payload_len  = len - payload_off;
            if (payload_len <= 0) return 0;
            if (!memmem(pkt + payload_off, payload_len,
                        r->string_match, strlen(r->string_match)))
                return 0;
        }
        if (r->tcp_flags[0] != '\0' && strcmp(r->tcp_flags, "0") != 0) return 0;
    } else {
        /* ICMP/other */
        if (r->dest_port != 0) return 0;
        if (r->tcp_flags[0] != '\0' && strcmp(r->tcp_flags, "0") != 0) return 0;
        if (r->string_match[0] != '\0' && strcmp(r->string_match, "0") != 0) {
            int payload_off  = eth_hdr_len + ip_hdr_len;
            int payload_len  = len - payload_off;
            if (payload_len <= 0) return 0;
            if (!memmem(pkt + payload_off, payload_len,
                        r->string_match, strlen(r->string_match)))
                return 0;
        }
    }
    return 1;
}

/* ── Token bucket rate limiter (per-rule) ──────────────────────────────── */

static int rate_limit_check(rule_t *r, int pkt_bytes) {
    if (r->rate_limit_bps == 0 && r->rate_limit_pps == 0) return 1;

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    double elapsed = (now.tv_sec  - r->last_refill.tv_sec) +
                     (now.tv_nsec - r->last_refill.tv_nsec) / 1e9;
    if (elapsed > 0) {
        if (r->rate_limit_bps > 0) {
            r->tokens_bytes += (uint64_t)(elapsed * r->rate_limit_bps);
            if (r->tokens_bytes > r->rate_limit_bps * 2)
                r->tokens_bytes = r->rate_limit_bps * 2;
        }
        if (r->rate_limit_pps > 0) {
            r->tokens_pkts += (uint64_t)(elapsed * r->rate_limit_pps);
            if (r->tokens_pkts > r->rate_limit_pps * 2)
                r->tokens_pkts = r->rate_limit_pps * 2;
        }
        r->last_refill = now;
    }
    if (r->rate_limit_bps > 0 && r->tokens_bytes < (uint64_t)pkt_bytes) {
        r->drop_count++; return 0;
    }
    if (r->rate_limit_pps > 0 && r->tokens_pkts < 1) {
        r->drop_count++; return 0;
    }
    if (r->rate_limit_bps > 0) r->tokens_bytes -= pkt_bytes;
    if (r->rate_limit_pps > 0) r->tokens_pkts  -= 1;
    return 1;
}

/* ── Resolve iface name → XSK (prefer matching queue; fallback to first) ── */

static xsk_info_t *xsk_for_iface_queue(const char *name, uint32_t queue_hint) {
    xsk_info_t *fallback = NULL;
    for (int i = 0; i < g_num_xsks; i++) {
        if (strcmp(g_xsks[i]->ifname, name) != 0) continue;
        if (g_xsks[i]->queue_id == queue_hint) return g_xsks[i];
        if (!fallback) fallback = g_xsks[i];
    }
    return fallback;
}

static xsk_info_t *xsk_for_iface(const char *name) {
    return xsk_for_iface_queue(name, 0);
}

/* Count RX queues for an interface via /sys/class/net/<name>/queues/rx-* */
static int iface_rx_queue_count(const char *name) {
    char path[256];
    snprintf(path, sizeof path, "/sys/class/net/%s/queues", name);
    DIR *d = opendir(path);
    if (!d) return 1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, "rx-", 3) == 0) n++;
    }
    closedir(d);
    return n > 0 ? n : 1;
}

/* ── TX submission: addr is into the shared UMEM (could be RX-arrived or
 *    freshly allocated). On failure (TX ring full) the addr is returned
 *    to the global free pool. ─────────────────────────────────────────── */

static void tx_submit(xsk_info_t *out, uint64_t addr, int len) {
    uint32_t idx;
    if (xsk_ring_prod__reserve(&out->tx, 1, &idx) != 1) {
        out->tx_dropped++;
        global_free(addr);
        return;
    }
    struct xdp_desc *d = xsk_ring_prod__tx_desc(&out->tx, idx);
    d->addr = addr;
    d->len  = (uint32_t)len;
    xsk_ring_prod__submit(&out->tx, 1);
    out->tx_packets++;
    out->tx_bytes += len;
    if (xsk_ring_prod__needs_wakeup(&out->tx))
        sendto(xsk_socket__fd(out->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
}

/* Forward a packet according to rule.
 *   `orig_addr`     — UMEM addr of the RX frame
 *   `pkt`/`len`     — pointer + length of that RX frame's data
 *   `can_consume`   — caller permits us to TX the original frame in-place
 *                     (true for the first matching rule, false thereafter
 *                      so that two outputs don't both reference the same
 *                      UMEM slot — that would be a use-after-free)
 *   `zc_out`/`zc_len` — out-params for a DEFERRED zero-copy submit. When the
 *                     original frame is eligible to be sent in place we do
 *                     NOT submit it here; we record the target XSK + length
 *                     and return 1. The caller submits it AFTER the rule loop
 *                     finishes, so `pkt` is never read once the frame has been
 *                     handed to the kernel's TX ring (which may DMA-overwrite
 *                     the shared UMEM slot). Submitting in-place mid-loop was a
 *                     use-after-return-to-kernel.
 * Returns 1 if we reserved `orig_addr` for deferred zero-copy (caller must
 * NOT recycle it, and must perform the deferred tx_submit). */
static int forward_packet(rule_t *r, uint64_t orig_addr,
                          const uint8_t *pkt, int len, int can_consume,
                          uint32_t src_queue,
                          xsk_info_t **zc_out, int *zc_len) {
    (void)orig_addr;
    if (!rate_limit_check(r, len)) return 0;

    /* Prefer the output XSK on the same queue index as our RX queue —
     * reduces TX-ring contention when multiple RX workers send to the
     * same output iface in parallel. */
    xsk_info_t *out = xsk_for_iface_queue(r->iface_out, src_queue);
    if (!out) return 0;

    int has_manip = (r->vlan_action != VLAN_NONE) ||
                    (r->truncate > 0 && r->truncate < len);

    if (can_consume && !has_manip) {
        /* Defer the zero-copy submit until the rule loop is done — see the
         * comment above. We only reserve the frame here. */
        *zc_out = out;
        *zc_len = len;
        return 1;
    }

    /* Manipulated, or this is the 2nd+ output (mirror) — allocate fresh. */
    uint64_t b = global_alloc();
    if (b == INVALID_UMEM_FRAME) { out->tx_dropped++; return 0; }
    uint8_t *bbuf = xsk_umem__get_data(g_umem.buffer, b);
    int out_len = len;
    switch (r->vlan_action) {
        case VLAN_ADD:
            out_len = vlan_tag_add   (pkt, len, r->vlan_new_id, bbuf, FRAME_SIZE); break;
        case VLAN_REMOVE:
            out_len = vlan_tag_remove(pkt, len, bbuf, FRAME_SIZE); break;
        case VLAN_CHANGE:
            out_len = vlan_tag_change(pkt, len, r->vlan_new_id, bbuf, FRAME_SIZE); break;
        default:
            memcpy(bbuf, pkt, len);
    }
    if (r->truncate > 0 && out_len > r->truncate) out_len = r->truncate;
    tx_submit(out, b, out_len);
    return 0;
}

/* ── Drain own completion ring → return frames to global free pool ─────── */

static void drain_cq(xsk_info_t *x) {
    uint32_t idx;
    uint32_t n = xsk_ring_cons__peek(&x->cq, TX_BATCH_SIZE, &idx);
    if (n == 0) return;
    for (uint32_t i = 0; i < n; i++) {
        uint64_t a = *xsk_ring_cons__comp_addr(&x->cq, idx + i);
        global_free(a);
    }
    xsk_ring_cons__release(&x->cq, n);
}

/* ── Refill own fq from global pool (keeps kernel RX fed) ──────────────── */

static void refill_fq(xsk_info_t *x) {
    uint32_t free_in_ring = xsk_prod_nb_free(&x->fq, FQ_REFILL_HI);
    if (free_in_ring < FQ_REFILL_LO) return;          /* still topped up */
    if (free_in_ring > FQ_REFILL_HI) free_in_ring = FQ_REFILL_HI;

    uint64_t addrs[FQ_REFILL_HI];
    uint32_t got = global_alloc_batch(addrs, free_in_ring);
    if (got == 0) return;

    uint32_t idx;
    if (xsk_ring_prod__reserve(&x->fq, got, &idx) != got) {
        /* Couldn't reserve all — return them to pool */
        for (uint32_t i = 0; i < got; i++) global_free(addrs[i]);
        return;
    }
    for (uint32_t i = 0; i < got; i++)
        *xsk_ring_prod__fill_addr(&x->fq, idx + i) = addrs[i];
    xsk_ring_prod__submit(&x->fq, got);
}

/* ── RX poll loop (per interface thread) ───────────────────────────────── */

static void *rx_worker(void *arg) {
    xsk_info_t *x = (xsk_info_t *)arg;
    struct pollfd pfd = { .fd = xsk_socket__fd(x->xsk), .events = POLLIN };

    plog("INFO", "RX worker started for %s queue %u", x->ifname, x->queue_id);

    while (g_running) {
        drain_cq(x);     /* return TX-completed frames to global pool */
        refill_fq(x);    /* keep kernel RX fed from global pool       */

        uint32_t idx_rx = 0;
        uint32_t nrx = xsk_ring_cons__peek(&x->rx, RX_BATCH_SIZE, &idx_rx);
        if (nrx == 0) { (void)poll(&pfd, 1, 100); continue; }

        for (uint32_t i = 0; i < nrx; i++) {
            const struct xdp_desc *d = xsk_ring_cons__rx_desc(&x->rx, idx_rx + i);
            uint64_t addr = d->addr;
            uint32_t len  = d->len;

            /* libxdp contract says len <= FRAME_SIZE but the kernel does not
             * enforce it; defensive clamp avoids OOB memcpy in forward_packet
             * if a misbehaving driver / co-loaded eBPF prog returns garbage. */
            if (len == 0 || len > FRAME_SIZE) {
                x->rx_dropped++;
                uint32_t fidx;
                if (xsk_ring_prod__reserve(&x->fq, 1, &fidx) == 1) {
                    *xsk_ring_prod__fill_addr(&x->fq, fidx) = addr;
                    xsk_ring_prod__submit(&x->fq, 1);
                } else {
                    global_free(addr);
                }
                continue;
            }

            uint8_t *pkt  = xsk_umem__get_data(g_umem.buffer, addr);

            x->rx_packets++;
            x->rx_bytes += len;

            /* Dedup gate (CRC32 over first N bytes; drops near-duplicates
             * arriving within g_dedup_window_us). */
            if (g_dedup_enabled && is_duplicate(pkt, (int)len)) {
                x->rx_dropped++;
                /* Recycle the frame; not forwarded */
                uint32_t fidx;
                if (xsk_ring_prod__reserve(&x->fq, 1, &fidx) == 1) {
                    *xsk_ring_prod__fill_addr(&x->fq, fidx) = addr;
                    xsk_ring_prod__submit(&x->fq, 1);
                } else {
                    global_free(addr);
                }
                continue;
            }

            /* L7 classification + DPI rule action (drop / forward / mirror).
             * "drop" short-circuits the packet entirely. "forward" forwards
             * to the dpi rule's output and skips the normal rule pipeline.
             * "mirror" forwards to dpi output but lets normal rules also fire. */
            const char *l7 = l7_classify(pkt, (int)len);
            dpi_record(l7, (int)len);
            int dpi_skip_rules = 0;
            int dpi_consumed   = 0;
            /* Snapshot DPI rules under the lock to avoid a torn read race
             * with load_dpi_config() — strncpy + count++ in the previous
             * implementation could leave proto[] non-NUL-terminated and
             * the strcmp below would walk off the buffer. */
            dpi_rule_t dpi_snap[DPI_STATS_SIZE];
            int dpi_snap_n = 0;
            pthread_mutex_lock(&g_dpi_lock);
            dpi_snap_n = g_dpi_rule_count;
            if (dpi_snap_n > 0) {
                memcpy(dpi_snap, g_dpi_rules, sizeof(dpi_rule_t) * (size_t)dpi_snap_n);
            }
            pthread_mutex_unlock(&g_dpi_lock);

            if (dpi_snap_n > 0 && strcmp(l7, "unknown") != 0) {
                for (int di = 0; di < dpi_snap_n; di++) {
                    if (strcmp(dpi_snap[di].proto, l7) != 0) continue;
                    if (strcmp(dpi_snap[di].action, "drop") == 0) {
                        x->rx_dropped++;
                        dpi_skip_rules = 1; dpi_consumed = 0; break;
                    }
                    if (strcmp(dpi_snap[di].action, "forward") == 0 ||
                        strcmp(dpi_snap[di].action, "mirror")  == 0) {
                        xsk_info_t *out = xsk_for_iface(dpi_snap[di].output);
                        if (out) {
                            /* Allocate a fresh frame since dpi forward is
                             * independent of normal rule chain ownership. */
                            uint64_t b = global_alloc();
                            if (b != INVALID_UMEM_FRAME) {
                                memcpy(xsk_umem__get_data(g_umem.buffer, b), pkt, len);
                                tx_submit(out, b, (int)len);
                            } else {
                                out->tx_dropped++;
                            }
                        }
                        if (strcmp(dpi_snap[di].action, "forward") == 0) {
                            dpi_skip_rules = 1; break;
                        }
                    }
                }
            }

            int original_consumed = 0;
            xsk_info_t *zc_out = NULL;   /* deferred zero-copy target */
            int        zc_len  = 0;
            if (dpi_skip_rules) goto recycle;
            pthread_mutex_lock(&g_rules_lock);
            for (int ri = 0; ri < g_num_rules; ri++) {
                rule_t *r = &g_rules[ri];
                if (strcmp(r->iface_in, x->ifname) != 0) continue;

                int matched = match_rule(r, pkt, len);
                if (r->exclude) matched = !matched;
                if (!matched) continue;

                r->match_count++;
                if (forward_packet(r, addr, pkt, (int)len, !original_consumed,
                                   x->queue_id, &zc_out, &zc_len))
                    original_consumed = 1;
            }
            pthread_mutex_unlock(&g_rules_lock);

            /* Perform the deferred zero-copy submit now that no further reads
             * of `pkt` will happen — the frame is handed to the kernel here. */
            if (zc_out) tx_submit(zc_out, addr, zc_len);

recycle:
            (void)dpi_consumed;
            if (!original_consumed) {
                /* Not forwarded by any rule — recycle RX frame to our fq. */
                uint32_t fidx;
                if (xsk_ring_prod__reserve(&x->fq, 1, &fidx) == 1) {
                    *xsk_ring_prod__fill_addr(&x->fq, fidx) = addr;
                    xsk_ring_prod__submit(&x->fq, 1);
                } else {
                    global_free(addr);
                }
            }
            /* else: addr is in transit on some peer's TX ring; will return
             * to the global pool via that peer's cq drain. */
        }
        xsk_ring_cons__release(&x->rx, nrx);
    }

    plog("INFO", "RX worker exiting for %s", x->ifname);
    return NULL;
}

/* ── Aggregate per-iface stats across all queues, write JSON snapshot ──── */

static void write_stats_json(void) {
    /* Aggregate per-iface across queues */
    char ifaces[MAX_INTERFACES][IF_NAMESIZE] = {{0}};
    uint64_t agg_rxp[MAX_INTERFACES] = {0};
    uint64_t agg_rxb[MAX_INTERFACES] = {0};
    uint64_t agg_txp[MAX_INTERFACES] = {0};
    uint64_t agg_txb[MAX_INTERFACES] = {0};
    uint64_t agg_rxd[MAX_INTERFACES] = {0};
    uint64_t agg_txd[MAX_INTERFACES] = {0};
    int nifaces = 0;

    for (int i = 0; i < g_num_xsks; i++) {
        xsk_info_t *x = g_xsks[i];
        int idx = -1;
        for (int j = 0; j < nifaces; j++)
            if (strcmp(ifaces[j], x->ifname) == 0) { idx = j; break; }
        if (idx < 0 && nifaces < MAX_INTERFACES) {
            idx = nifaces++;
            strncpy(ifaces[idx], x->ifname, IF_NAMESIZE - 1);
        }
        if (idx < 0) continue;
        agg_rxp[idx] += x->rx_packets;
        agg_rxb[idx] += x->rx_bytes;
        agg_txp[idx] += x->tx_packets;
        agg_txb[idx] += x->tx_bytes;
        agg_rxd[idx] += x->rx_dropped;
        agg_txd[idx] += x->tx_dropped;
    }

    /* Atomic-ish write: tmp then rename. */
    char tmp[256];
    snprintf(tmp, sizeof tmp, "%s.tmp", STATS_FILE);
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    fprintf(f, "{\"mode\":\"afxdp\",\"ts\":%ld,\"ifaces\":{", (long)time(NULL));
    for (int i = 0; i < nifaces; i++) {
        fprintf(f,
                "%s\"%s\":{\"rx_pkts\":%llu,\"rx_bytes\":%llu,"
                "\"tx_pkts\":%llu,\"tx_bytes\":%llu,"
                "\"rx_drop\":%llu,\"tx_drop\":%llu}",
                i == 0 ? "" : ",",
                ifaces[i],
                (unsigned long long)agg_rxp[i],
                (unsigned long long)agg_rxb[i],
                (unsigned long long)agg_txp[i],
                (unsigned long long)agg_txb[i],
                (unsigned long long)agg_rxd[i],
                (unsigned long long)agg_txd[i]);
    }
    fputs("}}", f);
    fclose(f);
    rename(tmp, STATS_FILE);
}

/* ── Stats thread ──────────────────────────────────────────────────────── */

static void *stats_worker(void *arg) {
    (void)arg;
    while (g_running) {
        sleep(STATS_INTERVAL);
        rules_check_reload();
        load_dedup_config();
        load_dpi_config();
        write_stats_json();
        for (int i = 0; i < g_num_xsks; i++) {
            xsk_info_t *x = g_xsks[i];
            plog("INFO",
                 "stats iface=%s q=%u rx_pkts=%llu rx_bytes=%llu tx_pkts=%llu tx_bytes=%llu rx_drop=%llu tx_drop=%llu",
                 x->ifname, x->queue_id,
                 (unsigned long long)x->rx_packets,
                 (unsigned long long)x->rx_bytes,
                 (unsigned long long)x->tx_packets,
                 (unsigned long long)x->tx_bytes,
                 (unsigned long long)x->rx_dropped,
                 (unsigned long long)x->tx_dropped);
        }
    }
    return NULL;
}

/* ── rlimit bump for locked memory (UMEM mmap) ─────────────────────────── */

static void bump_memlock(void) {
    struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &r) != 0)
        plog("WARN", "setrlimit MEMLOCK failed: %s", strerror(errno));
}

/* ── Status file management ────────────────────────────────────────────── */

static void status_write(const char *s) {
    FILE *f = fopen(STATUS_FILE, "w");
    if (!f) return;
    fputs(s, f);
    fclose(f);
}

/* ── Main ──────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    plog("INFO", "Packet Broker AF_XDP starting (pid=%d)", getpid());
    status_write("running");

    /* Save pid */
    FILE *pf = fopen(PID_FILE, "w");
    if (pf) { fprintf(pf, "%d\n", getpid()); fclose(pf); }

    bump_memlock();
    rules_load();
    load_dedup_config();
    load_dpi_config();

    /* CLI: positional iface args + optional --allow-mgmt
     *   ./packet_broker_afxdp [--allow-mgmt] <iface1> [iface2 ...]
     */
    char *ifaces[MAX_INTERFACES];
    int   nifaces = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--allow-mgmt") == 0) {
            g_allow_mgmt = 1;
        } else if (nifaces < MAX_INTERFACES) {
            ifaces[nifaces++] = argv[i];
        }
    }
    if (nifaces == 0) {
        plog("ERROR", "usage: %s [--allow-mgmt] <iface1> [iface2 ...]", argv[0]);
        return 2;
    }

    /* Guard: refuse to attach XDP to the cable-side management port
     * (would lock the operator out — see physical_server feedback memory). */
    for (int i = 0; i < nifaces; i++) {
        if (iface_is_management(ifaces[i]) && !g_allow_mgmt) {
            plog("ERROR",
                 "%s is a management interface (has IPv4 / default route). "
                 "Attaching XDP here would lock the operator out. "
                 "Re-run with --allow-mgmt if you really mean to do this.",
                 ifaces[i]);
            return 7;
        }
    }

    if (umem_global_init() != 0) {
        plog("ERROR", "Shared UMEM init failed");
        return 3;
    }

    /* Open one XSK per RX queue on each iface (multi-queue + RSS).
     * The kernel's default RSS hash distributes incoming flows across
     * the NIC's RX queues; each queue gets its own XSK so we get
     * parallel RX workers — scaling with core count. */
    int is_first = 1;
    for (int i = 0; i < nifaces; i++) {
        int nq = iface_rx_queue_count(ifaces[i]);
        if (nq > MAX_QUEUES_PER_IFACE) nq = MAX_QUEUES_PER_IFACE;
        plog("INFO", "iface %s: %d RX queue(s) detected → opening %d XSK(s)",
             ifaces[i], iface_rx_queue_count(ifaces[i]), nq);

        for (int q = 0; q < nq && g_num_xsks < MAX_XSKS; q++) {
            xsk_info_t *x = xsk_open(ifaces[i], (uint32_t)q, is_first);
            if (!x) {
                if (q == 0) {
                    plog("ERROR", "XSK setup failed for %s q0", ifaces[i]);
                    return 4;
                }
                /* Failure on a non-first queue is non-fatal — the iface still
                 * has queue 0 covered, just fewer parallel RX paths. */
                plog("WARN", "XSK setup failed for %s q%d — continuing", ifaces[i], q);
                break;
            }
            g_xsks[g_num_xsks++] = x;
            is_first = 0;
        }
    }

    /* RX worker per XSK + 1 stats thread */
    pthread_t rx_tids[MAX_XSKS];
    for (int i = 0; i < g_num_xsks; i++) {
        if (pthread_create(&rx_tids[i], NULL, rx_worker, g_xsks[i]) != 0) {
            plog("ERROR", "pthread_create RX[%d] failed: %s", i, strerror(errno));
            return 5;
        }
    }
    pthread_t stats_tid;
    pthread_create(&stats_tid, NULL, stats_worker, NULL);

    /* Block until signaled */
    while (g_running) pause();

    plog("INFO", "Shutting down ...");
    for (int i = 0; i < g_num_xsks; i++) pthread_join(rx_tids[i], NULL);
    pthread_join(stats_tid, NULL);

    /* Free per-rule BPF programs */
    for (int i = 0; i < g_num_rules; i++) {
        if (g_rules[i].bpf_handle) {
            pb_bpf_free(g_rules[i].bpf_handle);
            g_rules[i].bpf_handle = NULL;
        }
    }
    for (int i = 0; i < g_num_xsks; i++) {
        xsk_socket__delete(g_xsks[i]->xsk);
        free(g_xsks[i]);
    }
    if (g_umem.umem) xsk_umem__delete(g_umem.umem);
    if (g_umem.buffer && g_umem.buffer != MAP_FAILED)
        munmap(g_umem.buffer, (size_t)NUM_FRAMES * FRAME_SIZE);
    pthread_mutex_destroy(&g_umem.lock);

    status_write("stopped");
    unlink(PID_FILE);
    plog("INFO", "Packet Broker AF_XDP stopped");
    if (g_logf) fclose(g_logf);
    return 0;
}
