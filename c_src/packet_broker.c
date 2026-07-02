/*
 * Packet Broker — DPDK edition
 *
 * Kernel-bypass packet forwarding at feature parity with the libpcap and
 * AF_XDP data planes: extended rule matching (MAC / VLAN / IP+CIDR / proto /
 * src+dst port / TCP flags / string / cBPF / exclude), VLAN add/remove/change,
 * truncation, mirror & load-balance (via multiple rules), deduplication,
 * per-rule token-bucket rate limiting, L7/DPI classification + routing, hot
 * config reload, per-port stats JSON, and per-rule stats.
 *
 * RUNTIME PREREQUISITES (operator-provided, NOT turnkey):
 *   - hugepages configured, and the data-plane NICs bound to a DPDK-capable
 *     driver (vfio-pci for igc/i40e). NEVER bind the management NIC — doing so
 *     drops your SSH/UI. A vfio-bound NIC disappears from the kernel, so the
 *     web UI's interface pickers / netstats (which read /sys) cannot see it;
 *     DPDK ports are addressed by port-id. Closing that UI gap is tracked
 *     control-plane work — until then DPDK is opt-in.
 *   - The control plane launches this only when BROKER_MODE=dpdk AND
 *     PB_DPDK_EXPERIMENTAL=1 are set, and passes EAL args (see PB_DPDK_EAL).
 *
 * Extended CSV format (fields 1–8 required, 9–20 optional):
 *   interface_in, tcp_flags, dest_port, protocol, vlan_id, string_match,
 *   exclude, interface_out, enabled, priority, vlan_action, vlan_new_id,
 *   truncate, src_ip, dst_ip, src_mac, dst_mac, bpf_filter, rate_mbps,
 *   rate_pps  (interface_in/out = DPDK port-id strings "0","1",…; field 21
 *   src_port is appended after rate_pps)
 *
 * Build:
 *   gcc -O2 packet_broker.c bpf_helpers.c -o packet_broker_dpdk \
 *       $(pkg-config --cflags --libs libdpdk) -lpcap -lpthread
 * Run (after hugepage + NIC-bind setup):
 *   PB_DPDK_EXPERIMENTAL=1 sudo ./packet_broker_dpdk -l 0-3 -n 4 --
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <time.h>
#include <pthread.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_lcore.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_memcpy.h>

#include "bpf_helpers.h" /* opaque cBPF compile/match (libpcap-backed) */

/* ── Constants ─────────────────────────────────────────────────────────── */

#define MAX_RULES       256
#define MAX_PORTS       64
#define FIELD_LEN       64
#define BPF_LEN         256
#define LINE_LEN        1024
#define RULE_FILE       "rules.conf"
#define DEDUP_CONF_FILE "dedup.conf"
#define DPI_CONF_FILE   "dpi.conf"
#define LOG_FILE        "packet_broker.log"
#define STATUS_FILE     "packet_broker.status"
#define PID_FILE        "packet_broker.pid"
#define STATS_FILE      "packet_broker_afxdp.stats.json" /* UI reads this path */

#define RX_RING_SIZE    1024
#define TX_RING_SIZE    1024
#define NUM_MBUFS       8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE      32
#define SNAP_LEN        65535

#define ETHERTYPE_VLAN_ID  0x8100
#define ETH_HDR_MIN  14
#define VLAN_HDR_MIN 18

enum vlan_action { VLAN_NONE = 0, VLAN_ADD = 1, VLAN_REMOVE = 2, VLAN_CHANGE = 3 };

/* ── Rule structure ────────────────────────────────────────────────────── */

typedef struct {
    uint16_t port_in;
    uint16_t port_out;
    char     tcp_flags[FIELD_LEN];
    int      dest_port;
    int      src_port;
    char     protocol[FIELD_LEN];
    int      vlan_id;
    char     string_match[FIELD_LEN];
    int      exclude;

    int      enabled;
    int      priority;
    int      vlan_action;
    int      vlan_new_id;
    int      truncate;

    uint32_t src_ip, src_mask, dst_ip, dst_mask;
    uint8_t  src_mac[6], dst_mac[6];
    int      has_src_mac, has_dst_mac;

    char     bpf_filter[BPF_LEN];
    void    *bpf_handle;        /* compiled cBPF, NULL = none */

    uint64_t rate_limit_bps;    /* bytes/sec, 0 = unlimited */
    uint64_t rate_limit_pps;    /* pkts/sec, 0 = unlimited */
    uint64_t tokens_bytes, tokens_pkts;
    struct timespec last_refill;

    uint64_t match_count, byte_count, drop_count;
} rule_t;

/* ── Globals ───────────────────────────────────────────────────────────── */

static rule_t    rules[MAX_RULES];
static int       rule_count = 0;
static time_t    last_modified = 0;
static volatile int running = 1;
static FILE     *log_fp = NULL;
static struct rte_mempool *mbuf_pool;
static uint16_t  g_nb_ports = 0;
static char      g_rootdir[512] = ".";

/* Concurrency: one worker lcore per RX port (each port owned by exactly one
 * worker, so per-rule stats/tokens are lock-free). g_cfg_lock guards the
 * rules/dpi/dedup config during a reload (workers rd-lock per burst, the main
 * lcore wr-locks while swapping). g_dedup_lock guards the shared dedup table. */
static pthread_rwlock_t g_cfg_lock   = PTHREAD_RWLOCK_INITIALIZER;
static pthread_mutex_t  g_dedup_lock = PTHREAD_MUTEX_INITIALIZER;

/* Management port-ids that rules may never bind (CSV in PB_DPDK_MGMT_PORTS).
 * Mirrors the netifaces mgmt-exclusion the libpcap/AF_XDP variants get via the
 * UI: a rule referencing a mgmt port is dropped at load time. */
static int g_mgmt_ports[MAX_PORTS];
static int g_mgmt_nports = 0;

static int is_mgmt_port(int p) {
    for (int i = 0; i < g_mgmt_nports; i++) if (g_mgmt_ports[i] == p) return 1;
    return 0;
}

/* Each worker TXes only on its own queue index on every port, so concurrent
 * forwards from different RX workers to one output port never share a TX queue
 * (rte_eth_tx_burst is not queue-thread-safe). */
static int g_num_workers = 1;

/* Per-port counters for the stats JSON the UI consumes. */
static uint64_t  port_rx_pkts[MAX_PORTS], port_rx_bytes[MAX_PORTS];
static uint64_t  port_tx_pkts[MAX_PORTS], port_tx_bytes[MAX_PORTS];
static uint64_t  port_rx_drop[MAX_PORTS], port_tx_drop[MAX_PORTS];

/* ── Logging ───────────────────────────────────────────────────────────── */

static void log_msg(const char *fmt, ...) {
    if (!log_fp) return;
    va_list ap;
    va_start(ap, fmt);
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    fprintf(log_fp, "%04d/%02d/%02d %02d:%02d:%02d ",
            tmv.tm_year+1900, tmv.tm_mon+1, tmv.tm_mday,
            tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
    vfprintf(log_fp, fmt, ap);
    fprintf(log_fp, "\n");
    fflush(log_fp);
    va_end(ap);
}

static void write_file(const char *path, const char *content) {
    FILE *f = fopen(path, "w");
    if (f) { fputs(content, f); fclose(f); }
}

static void handle_signal(int sig) { (void)sig; running = 0; }

/* ── Parsing helpers ───────────────────────────────────────────────────── */

static void trim(char *s) {
    char *p = s;
    while (*p == ' ' || *p == '\t') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    int len = strlen(s);
    while (len > 0 && (s[len-1] == ' ' || s[len-1] == '\t' ||
                       s[len-1] == '\r' || s[len-1] == '\n'))
        s[--len] = '\0';
}

static int parse_cidr(const char *s, uint32_t *ip, uint32_t *mask) {
    if (!s || !*s || strcmp(s, "0") == 0) { *ip = 0; *mask = 0; return 0; }
    char buf[64];
    strncpy(buf, s, sizeof(buf)-1); buf[sizeof(buf)-1] = '\0';
    char *slash = strchr(buf, '/');
    int prefix = 32;
    if (slash) { *slash = '\0'; prefix = atoi(slash + 1); }
    if (prefix < 0) prefix = 0;
    if (prefix > 32) prefix = 32;
    struct in_addr addr;
    if (inet_aton(buf, &addr) == 0) { *ip = 0; *mask = 0; return -1; }
    *ip = addr.s_addr;
    *mask = prefix == 0 ? 0 : htonl(~((1u << (32 - prefix)) - 1));
    return 0;
}

static int parse_mac(const char *s, uint8_t mac[6]) {
    if (!s || !*s || strcmp(s, "0") == 0) return 0;
    unsigned int m[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &m[0],&m[1],&m[2],&m[3],&m[4],&m[5]) != 6)
        return 0;
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)m[i];
    return 1;
}

static int parse_vlan_action(const char *s) {
    if (!s || !*s || strcmp(s, "none") == 0 || strcmp(s, "0") == 0) return VLAN_NONE;
    if (strcmp(s, "add") == 0)    return VLAN_ADD;
    if (strcmp(s, "remove") == 0) return VLAN_REMOVE;
    if (strcmp(s, "change") == 0) return VLAN_CHANGE;
    return VLAN_NONE;
}

/* ── L7 / DPI classification (port-equivalent to the libpcap variant) ───── */

static const char *detect_l7_protocol(const uint8_t *payload, int len,
                                       int ip_proto, int src_port, int dst_port) {
    if (len < 2) return "unknown";
    if ((dst_port == 53 || src_port == 53) && ip_proto == IPPROTO_UDP && len >= 12) return "dns";
    if ((dst_port == 123 || src_port == 123) && ip_proto == IPPROTO_UDP) return "ntp";
    if ((dst_port == 161 || dst_port == 162 || src_port == 161) && ip_proto == IPPROTO_UDP) return "snmp";
    if (dst_port == 3389 || src_port == 3389) return "rdp";
    if ((dst_port == 502 || src_port == 502) && len >= 7 && payload[2] == 0x00 && payload[3] == 0x00) return "modbus";
    if ((dst_port == 20000 || src_port == 20000) && len >= 2 && payload[0] == 0x05 && payload[1] == 0x64) return "dnp3";
    if ((dst_port == 102 || src_port == 102) && len >= 4 && payload[0] == 0x03 && payload[1] == 0x00) return "s7comm";
    if ((dst_port == 44818 || src_port == 44818 || dst_port == 2222 || src_port == 2222) && len >= 4) return "enip";
    if ((dst_port == 47808 || src_port == 47808) && ip_proto == IPPROTO_UDP && len >= 4 && payload[0] == 0x81) return "bacnet";
    if ((dst_port == 4840 || src_port == 4840) && len >= 4 &&
        (memcmp(payload, "OPN", 3) == 0 || memcmp(payload, "HEL", 3) == 0 ||
         memcmp(payload, "ACK", 3) == 0 || memcmp(payload, "MSG", 3) == 0)) return "opcua";
    if ((dst_port == 2404 || src_port == 2404) && len >= 2 && payload[0] == 0x68) return "iec104";
    if ((dst_port == 9600 || src_port == 9600) && len >= 4 && (memcmp(payload, "FINS", 4) == 0 || payload[0] == 0x80)) return "fins";
    if ((dst_port == 5094 || src_port == 5094) && len >= 4) return "hartip";
    if (len >= 4 && (memcmp(payload, "GET ", 4) == 0 || memcmp(payload, "POST", 4) == 0 ||
        memcmp(payload, "PUT ", 4) == 0 || memcmp(payload, "HEAD", 4) == 0 ||
        memcmp(payload, "HTTP", 4) == 0 || memcmp(payload, "DELE", 4) == 0 ||
        memcmp(payload, "PATC", 4) == 0 || memcmp(payload, "OPTI", 4) == 0)) return "http";
    if (len >= 6 && payload[0] == 0x16 && payload[1] == 0x03 && payload[2] <= 0x04) return "tls";
    if (len >= 4 && memcmp(payload, "SSH-", 4) == 0) return "ssh";
    if (len >= 4 && (memcmp(payload, "220 ", 4) == 0 || memcmp(payload, "EHLO", 4) == 0 ||
        memcmp(payload, "HELO", 4) == 0 || memcmp(payload, "MAIL", 4) == 0)) return "smtp";
    if (len >= 4 && (dst_port == 21 || src_port == 21) &&
        (memcmp(payload, "220-", 4) == 0 || memcmp(payload, "220 ", 4) == 0 ||
         memcmp(payload, "USER", 4) == 0 || memcmp(payload, "PASS", 4) == 0)) return "ftp";
    if (len >= 2 && ((payload[0] & 0xF0) == 0x10 || (payload[0] & 0xF0) == 0x20) &&
        (dst_port == 1883 || dst_port == 8883 || src_port == 1883)) return "mqtt";
    if (len >= 7 && (memcmp(payload, "SIP/2.0", 7) == 0 || memcmp(payload, "INVITE ", 7) == 0)) return "sip";
    if (len >= 8 && (dst_port == 445 || src_port == 445) &&
        (payload[4] == 0xFF || payload[4] == 0xFE) && payload[5] == 'S' && payload[6] == 'M' && payload[7] == 'B') return "smb";
    if ((dst_port == 389 || dst_port == 636 || src_port == 389) && len >= 2 && payload[0] == 0x30) return "ldap";
    return "unknown";
}

#define DPI_MAX 64
typedef struct { char proto[32]; char action[16]; int output; } dpi_rule_t;
static dpi_rule_t dpi_rules[DPI_MAX];
static int        dpi_rule_count = 0;

static void load_dpi_config(void) {
    dpi_rule_t staged[DPI_MAX];
    int count = 0;
    FILE *f = fopen(DPI_CONF_FILE, "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f) && count < DPI_MAX) {
            char proto[32], action[16], output[FIELD_LEN];
            if (sscanf(line, "%31[^,],%15[^,],%63s", proto, action, output) >= 2) {
                memset(&staged[count], 0, sizeof(staged[count]));
                strncpy(staged[count].proto, proto, sizeof(staged[count].proto) - 1);
                strncpy(staged[count].action, action, sizeof(staged[count].action) - 1);
                staged[count].output = atoi(output);
                count++;
            }
        }
        fclose(f);
    }
    if (count > 0) memcpy(dpi_rules, staged, sizeof(dpi_rule_t) * (size_t)count);
    dpi_rule_count = count;
    if (count > 0) log_msg("Loaded %d DPI rules", count);
}

/* Classify a flat frame's L7 protocol (eth/VLAN/IP/TCP/UDP aware, bounds-safe). */
static const char *l7_classify(const uint8_t *pkt, int len) {
    if (len < ETH_HDR_MIN) return "unknown";
    int eth_hl = 14;
    uint16_t et;
    memcpy(&et, pkt + 12, 2); et = ntohs(et);
    if (et == ETHERTYPE_VLAN_ID) {
        if (len < VLAN_HDR_MIN) return "unknown";
        eth_hl = 18;
        memcpy(&et, pkt + 16, 2); et = ntohs(et);
    }
    if (et != 0x0800 || len < eth_hl + 20) return "unknown";
    const struct ip *iph = (const struct ip *)(pkt + eth_hl);
    int ip_hl = iph->ip_hl * 4;
    if (ip_hl < 20 || eth_hl + ip_hl > len) return "unknown";
    int sp = 0, dp = 0;
    const uint8_t *l7 = pkt + eth_hl + ip_hl;
    int l7_len = len - eth_hl - ip_hl;
    if (iph->ip_p == IPPROTO_TCP && len >= eth_hl + ip_hl + 20) {
        const struct tcphdr *t = (const struct tcphdr *)(pkt + eth_hl + ip_hl);
        sp = ntohs(t->th_sport); dp = ntohs(t->th_dport);
        int tcp_hl = t->th_off * 4;
        l7 = pkt + eth_hl + ip_hl + tcp_hl;
        l7_len = len - eth_hl - ip_hl - tcp_hl;
    } else if (iph->ip_p == IPPROTO_UDP && len >= eth_hl + ip_hl + 8) {
        const struct udphdr *u = (const struct udphdr *)(pkt + eth_hl + ip_hl);
        sp = ntohs(u->uh_sport); dp = ntohs(u->uh_dport);
        l7 = pkt + eth_hl + ip_hl + 8;
        l7_len = len - eth_hl - ip_hl - 8;
    }
    if (l7_len <= 0) return "unknown";
    return detect_l7_protocol(l7, l7_len, iph->ip_p, sp, dp);
}

/* ── Deduplication (single-threaded loop → no lock needed) ──────────────── */

#define DEDUP_TABLE_SIZE 65536
typedef struct { uint32_t hash; struct timespec seen; } dedup_entry_t;
static dedup_entry_t dedup_table[DEDUP_TABLE_SIZE];
static int dedup_enabled = 0;
static int dedup_window_us = 100000;
static int dedup_hash_bytes = 128;

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
    if (!dedup_enabled) return 0;
    int hash_len = len < dedup_hash_bytes ? len : dedup_hash_bytes;
    uint32_t h = crc32_calc(pkt, hash_len);
    int idx = h & (DEDUP_TABLE_SIZE - 1);
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    int dup = 0;
    pthread_mutex_lock(&g_dedup_lock); /* table is shared across worker lcores */
    dedup_entry_t *e = &dedup_table[idx];
    if (e->hash == h) {
        long elapsed_us = (now.tv_sec - e->seen.tv_sec) * 1000000L +
                          (now.tv_nsec - e->seen.tv_nsec) / 1000L;
        if (elapsed_us < dedup_window_us) dup = 1;
    }
    if (!dup) { e->hash = h; e->seen = now; }
    pthread_mutex_unlock(&g_dedup_lock);
    return dup;
}

static void load_dedup_config(void) {
    FILE *f = fopen(DEDUP_CONF_FILE, "r");
    if (!f) { dedup_enabled = 0; return; }
    char line[256];
    int any = 0;
    while (fgets(line, sizeof(line), f)) {
        char port[FIELD_LEN]; int en, wms, hb;
        if (sscanf(line, "%63[^,],%d,%d,%d", port, &en, &wms, &hb) >= 2) {
            if (en) { any = 1; if (wms > 0) dedup_window_us = wms * 1000; if (hb > 0) dedup_hash_bytes = hb; }
        }
    }
    fclose(f);
    dedup_enabled = any;
    if (any) log_msg("Dedup enabled: window=%dus hash=%dB", dedup_window_us, dedup_hash_bytes);
}

/* ── Token-bucket rate limiting ─────────────────────────────────────────── */

static int rate_limit_check(rule_t *r, int pkt_bytes) {
    if (r->rate_limit_bps == 0 && r->rate_limit_pps == 0) return 1;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    double elapsed = (now.tv_sec - r->last_refill.tv_sec) +
                     (now.tv_nsec - r->last_refill.tv_nsec) / 1e9;
    if (elapsed > 0) {
        if (r->rate_limit_bps > 0) {
            r->tokens_bytes += (uint64_t)(elapsed * r->rate_limit_bps);
            if (r->tokens_bytes > r->rate_limit_bps * 2) r->tokens_bytes = r->rate_limit_bps * 2;
        }
        if (r->rate_limit_pps > 0) {
            r->tokens_pkts += (uint64_t)(elapsed * r->rate_limit_pps);
            if (r->tokens_pkts > r->rate_limit_pps * 2) r->tokens_pkts = r->rate_limit_pps * 2;
        }
        r->last_refill = now;
    }
    if (r->rate_limit_bps > 0 && r->tokens_bytes < (uint64_t)pkt_bytes) { r->drop_count++; return 0; }
    if (r->rate_limit_pps > 0 && r->tokens_pkts < 1) { r->drop_count++; return 0; }
    if (r->rate_limit_bps > 0) r->tokens_bytes -= pkt_bytes;
    if (r->rate_limit_pps > 0) r->tokens_pkts--;
    return 1;
}

/* ── Load rules ────────────────────────────────────────────────────────── */

static void free_bpf_handles(void) {
    for (int i = 0; i < rule_count; i++)
        if (rules[i].bpf_handle) { pb_bpf_free(rules[i].bpf_handle); rules[i].bpf_handle = NULL; }
}

static void load_rules(void) {
    FILE *f = fopen(RULE_FILE, "r");
    if (!f) { log_msg("Cannot open %s", RULE_FILE); return; }

    rule_t new_rules[MAX_RULES];
    int count = 0;
    char line[LINE_LEN];

    while (fgets(line, sizeof(line), f) && count < MAX_RULES) {
        trim(line);
        if (line[0] == '\0' || line[0] == '#') continue;

        /* Manual comma-split PRESERVING empty fields — strtok() collapses
         * consecutive commas and misaligns columns when an optional field is
         * empty (what the Go control plane writes). Matches Go strings.Split. */
        char *fields[22];
        int nf = 0;
        fields[nf++] = line;
        for (char *p = line; nf < 22 && (p = strchr(p, ',')) != NULL; ) {
            *p++ = '\0';
            fields[nf++] = p;
        }
        for (int fi = 0; fi < nf; fi++) trim(fields[fi]);
        if (nf < 8) continue;

        rule_t *r = &new_rules[count];
        memset(r, 0, sizeof(rule_t));
        r->port_in  = (uint16_t)atoi(fields[0]);
        r->port_out = (uint16_t)atoi(fields[7]);
        strncpy(r->tcp_flags,    fields[1], FIELD_LEN-1);
        r->dest_port = atoi(fields[2]);
        strncpy(r->protocol,     fields[3], FIELD_LEN-1);
        r->vlan_id = atoi(fields[4]);
        strncpy(r->string_match, fields[5], FIELD_LEN-1);
        r->exclude = atoi(fields[6]);
        r->enabled      = nf > 8  ? atoi(fields[8])  : 1;
        r->priority     = nf > 9  ? atoi(fields[9])  : count;
        r->vlan_action  = nf > 10 ? parse_vlan_action(fields[10]) : VLAN_NONE;
        r->vlan_new_id  = nf > 11 ? atoi(fields[11]) : 0;
        r->truncate     = nf > 12 ? atoi(fields[12]) : 0;
        if (nf > 13) parse_cidr(fields[13], &r->src_ip, &r->src_mask);
        if (nf > 14) parse_cidr(fields[14], &r->dst_ip, &r->dst_mask);
        if (nf > 15) r->has_src_mac = parse_mac(fields[15], r->src_mac);
        if (nf > 16) r->has_dst_mac = parse_mac(fields[16], r->dst_mac);
        if (nf > 17 && fields[17][0] && strcmp(fields[17], "0") != 0)
            strncpy(r->bpf_filter, fields[17], BPF_LEN-1);
        if (nf > 18) {
            int mbps = atoi(fields[18]);
            if (mbps > 0) r->rate_limit_bps = (uint64_t)mbps * 125000ULL; /* Mbps→B/s */
        }
        if (nf > 19) r->rate_limit_pps = (uint64_t)atoi(fields[19]);
        if (nf > 20) r->src_port = atoi(fields[20]);
        if (r->rate_limit_bps > 0) r->tokens_bytes = r->rate_limit_bps;
        if (r->rate_limit_pps > 0) r->tokens_pkts = r->rate_limit_pps;
        clock_gettime(CLOCK_MONOTONIC, &r->last_refill);

        if (!r->enabled) continue;
        if (r->port_in >= g_nb_ports || r->port_out >= g_nb_ports) {
            log_msg("Rule %d: port %d/%d out of range (max %d), skipping",
                    count, r->port_in, r->port_out, g_nb_ports-1);
            continue;
        }
        if (is_mgmt_port(r->port_in) || is_mgmt_port(r->port_out)) {
            log_msg("Rule %d: references management port %d/%d — refused",
                    count, r->port_in, r->port_out);
            continue;
        }
        count++;
    }
    fclose(f);

    for (int i = 0; i < count - 1; i++)
        for (int j = i + 1; j < count; j++)
            if (new_rules[j].priority < new_rules[i].priority) {
                rule_t tmp = new_rules[i]; new_rules[i] = new_rules[j]; new_rules[j] = tmp;
            }

    /* Compile cBPF for the new set, then swap (freeing the old handles). */
    for (int i = 0; i < count; i++) {
        if (new_rules[i].bpf_filter[0]) {
            char err[128];
            new_rules[i].bpf_handle = pb_bpf_compile(new_rules[i].bpf_filter, err, sizeof err);
            if (!new_rules[i].bpf_handle)
                log_msg("BPF compile failed for rule %d ('%s'): %s", i, new_rules[i].bpf_filter, err);
        }
    }
    free_bpf_handles();
    memcpy(rules, new_rules, sizeof(rule_t) * count);
    rule_count = count;
    log_msg("Loaded %d rules", count);
}

static void check_for_updates(void) {
    struct stat st;
    if (stat(RULE_FILE, &st) == 0 && st.st_mtime != last_modified) {
        last_modified = st.st_mtime;
        log_msg("Rules file changed, reloading...");
        /* Exclude worker lcores while the rule/dpi/dedup config is swapped. */
        pthread_rwlock_wrlock(&g_cfg_lock);
        load_rules();
        load_dedup_config();
        load_dpi_config();
        pthread_rwlock_unlock(&g_cfg_lock);
    }
}

/* ── VLAN helpers (flat buffer, bounds-checked) ─────────────────────────── */

static int has_vlan_tag(const uint8_t *pkt, int len) {
    if (len < ETH_HDR_MIN) return 0;
    uint16_t et; memcpy(&et, pkt + 12, 2);
    return ntohs(et) == ETHERTYPE_VLAN_ID;
}
static int get_vlan_id(const uint8_t *pkt, int len) {
    if (len < VLAN_HDR_MIN) return 0;
    uint16_t tci; memcpy(&tci, pkt + 14, 2);
    return ntohs(tci) & 0x0FFF;
}
static int vlan_add(const uint8_t *pkt, int len, int vid, uint8_t *out, int out_sz) {
    if (len < ETH_HDR_MIN || len + 4 > out_sz) return len;
    memcpy(out, pkt, 12);
    out[12] = 0x81; out[13] = 0x00;
    uint16_t tci = htons((uint16_t)(vid & 0x0FFF));
    memcpy(out + 14, &tci, 2);
    memcpy(out + 16, pkt + 12, (size_t)(len - 12));
    return len + 4;
}
static int vlan_remove(const uint8_t *pkt, int len, uint8_t *out, int out_sz) {
    if (len < ETH_HDR_MIN || len > out_sz) return len;
    if (!has_vlan_tag(pkt, len) || len < VLAN_HDR_MIN) { memcpy(out, pkt, (size_t)len); return len; }
    memcpy(out, pkt, 12);
    memcpy(out + 12, pkt + 16, (size_t)(len - 16));
    return len - 4;
}
static int vlan_change(const uint8_t *pkt, int len, int new_vid, uint8_t *out, int out_sz) {
    if (len < ETH_HDR_MIN) return len;
    if (!has_vlan_tag(pkt, len) || len < VLAN_HDR_MIN) return vlan_add(pkt, len, new_vid, out, out_sz);
    if (len > out_sz) return len;
    memcpy(out, pkt, (size_t)len);
    uint16_t tci; memcpy(&tci, out + 14, 2);
    tci = ntohs(tci); tci = (tci & 0xF000) | (new_vid & 0x0FFF); tci = htons(tci);
    memcpy(out + 14, &tci, 2);
    return len;
}

/* ── Packet matching (flat buffer) ─────────────────────────────────────── */

static int match_rule(const rule_t *r, const uint8_t *pkt, int len) {
    if (len < ETH_HDR_MIN) return 0;
    int eth_hdr_len = 14;
    uint16_t ethertype;
    memcpy(&ethertype, pkt + 12, 2); ethertype = ntohs(ethertype);
    if (ethertype == ETHERTYPE_VLAN_ID) {
        if (len < VLAN_HDR_MIN) return 0;
        eth_hdr_len = 18;
        memcpy(&ethertype, pkt + 16, 2); ethertype = ntohs(ethertype);
    }

    if (r->has_dst_mac && memcmp(pkt, r->dst_mac, 6) != 0) return 0;
    if (r->has_src_mac && memcmp(pkt + 6, r->src_mac, 6) != 0) return 0;

    if (r->vlan_id != 0) {
        if (!has_vlan_tag(pkt, len)) return 0;
        if (get_vlan_id(pkt, len) != r->vlan_id) return 0;
    }

    /* cBPF filter (compiled at load time). De-tag an 802.1Q frame first so a
     * plain expression like "tcp port N" matches SPAN/mirror traffic — the tag
     * shifts the ethertype to offset 16 and would otherwise defeat the filter
     * (the structured fields above already skip the tag). */
    if (r->bpf_handle) {
        const uint8_t *fpkt = pkt;
        int flen = len;
        uint8_t detag[SNAP_LEN];
        uint16_t et0;
        memcpy(&et0, pkt + 12, 2);
        if (ntohs(et0) == ETHERTYPE_VLAN_ID && len >= VLAN_HDR_MIN) {
            int n = len - 4;
            if (n > (int)sizeof(detag)) n = (int)sizeof(detag);
            memcpy(detag, pkt, 12);
            memcpy(detag + 12, pkt + 16, (size_t)(n - 12));
            fpkt = detag;
            flen = n;
        }
        if (!pb_bpf_match(r->bpf_handle, fpkt, flen)) return 0;
    }

    if (ethertype != 0x0800) {
        if (r->dest_port != 0 || r->src_port != 0 ||
            (r->protocol[0] && strcmp(r->protocol, "0") != 0) ||
            r->src_ip != 0 || r->dst_ip != 0 ||
            (r->tcp_flags[0] && strcmp(r->tcp_flags, "0") != 0) ||
            (r->string_match[0] && strcmp(r->string_match, "0") != 0))
            return 0;
        return 1;
    }

    if (len < eth_hdr_len + 20) return 0;
    const struct ip *iph = (const struct ip *)(pkt + eth_hdr_len);
    int ip_hl = iph->ip_hl * 4;
    if (ip_hl < 20 || eth_hdr_len + ip_hl > len) return 0;

    if (r->src_ip && (iph->ip_src.s_addr & r->src_mask) != (r->src_ip & r->src_mask)) return 0;
    if (r->dst_ip && (iph->ip_dst.s_addr & r->dst_mask) != (r->dst_ip & r->dst_mask)) return 0;

    if (r->protocol[0] && strcmp(r->protocol, "0") != 0) {
        if (strcasecmp(r->protocol, "TCP") == 0  && iph->ip_p != IPPROTO_TCP)  return 0;
        if (strcasecmp(r->protocol, "UDP") == 0  && iph->ip_p != IPPROTO_UDP)  return 0;
        if (strcasecmp(r->protocol, "ICMP") == 0 && iph->ip_p != IPPROTO_ICMP) return 0;
    }

    if (iph->ip_p == IPPROTO_TCP && len >= eth_hdr_len + ip_hl + 20) {
        const struct tcphdr *tcp = (const struct tcphdr *)(pkt + eth_hdr_len + ip_hl);
        if (r->dest_port && ntohs(tcp->th_dport) != r->dest_port) return 0;
        if (r->src_port  && ntohs(tcp->th_sport) != r->src_port)  return 0;
        if (r->tcp_flags[0] && strcmp(r->tcp_flags, "0") != 0) {
            uint8_t fl = tcp->th_flags;
            for (const char *c = r->tcp_flags; *c; c++) {
                switch (*c) {
                    case 'S': if (!(fl & TH_SYN))  return 0; break;
                    case 'A': if (!(fl & TH_ACK))  return 0; break;
                    case 'F': if (!(fl & TH_FIN))  return 0; break;
                    case 'R': if (!(fl & TH_RST))  return 0; break;
                    case 'P': if (!(fl & TH_PUSH)) return 0; break;
                    case 'U': if (!(fl & TH_URG))  return 0; break;
                }
            }
        }
        if (r->string_match[0] && strcmp(r->string_match, "0") != 0) {
            int off = eth_hdr_len + ip_hl + tcp->th_off * 4;
            int plen = len - off;
            if (plen <= 0 || !memmem(pkt + off, plen, r->string_match, strlen(r->string_match))) return 0;
        }
    } else if (iph->ip_p == IPPROTO_UDP && len >= eth_hdr_len + ip_hl + 8) {
        const struct udphdr *udp = (const struct udphdr *)(pkt + eth_hdr_len + ip_hl);
        if (r->dest_port && ntohs(udp->uh_dport) != r->dest_port) return 0;
        if (r->src_port  && ntohs(udp->uh_sport) != r->src_port)  return 0;
        if (r->tcp_flags[0] && strcmp(r->tcp_flags, "0") != 0) return 0;
        if (r->string_match[0] && strcmp(r->string_match, "0") != 0) {
            int off = eth_hdr_len + ip_hl + 8;
            int plen = len - off;
            if (plen <= 0 || !memmem(pkt + off, plen, r->string_match, strlen(r->string_match))) return 0;
        }
    } else {
        if (r->dest_port || r->src_port) return 0;
        if (r->tcp_flags[0] && strcmp(r->tcp_flags, "0") != 0) return 0;
    }
    return 1;
}

/* ── Forward (zero-copy clone, or rebuild for manip/truncate) ───────────── */

static void tx_one(uint16_t port_out, uint16_t txq, struct rte_mbuf *m) {
    int blen = rte_pktmbuf_pkt_len(m);
    uint16_t sent = rte_eth_tx_burst(port_out, txq, &m, 1);
    if (sent == 0) { rte_pktmbuf_free(m); if (port_out < MAX_PORTS) __atomic_fetch_add(&port_tx_drop[port_out], 1, __ATOMIC_RELAXED); }
    else if (port_out < MAX_PORTS) {
        __atomic_fetch_add(&port_tx_pkts[port_out], 1, __ATOMIC_RELAXED);
        __atomic_fetch_add(&port_tx_bytes[port_out], blen, __ATOMIC_RELAXED);
    }
}

/* txq = the calling worker's dedicated TX-queue index on every port. */
static void forward_to(uint16_t port_out, uint16_t txq, int vlan_action, int vlan_new_id,
                       int truncate, struct rte_mbuf *m, const uint8_t *flat, int len) {
    if (vlan_action == VLAN_NONE && (truncate == 0 || len <= truncate)) {
        struct rte_mbuf *clone = rte_pktmbuf_clone(m, mbuf_pool);
        if (!clone) { if (port_out < MAX_PORTS) __atomic_fetch_add(&port_tx_drop[port_out], 1, __ATOMIC_RELAXED); return; }
        tx_one(port_out, txq, clone);
        return;
    }
    uint8_t buf[SNAP_LEN + 4];
    const uint8_t *out_pkt = flat;
    int out_len = len;
    switch (vlan_action) {
        case VLAN_ADD:    out_len = vlan_add(flat, len, vlan_new_id, buf, sizeof(buf)); out_pkt = buf; break;
        case VLAN_REMOVE: out_len = vlan_remove(flat, len, buf, sizeof(buf));           out_pkt = buf; break;
        case VLAN_CHANGE: out_len = vlan_change(flat, len, vlan_new_id, buf, sizeof(buf)); out_pkt = buf; break;
        default: break;
    }
    if (truncate > 0 && out_len > truncate) out_len = truncate;
    struct rte_mbuf *nm = rte_pktmbuf_alloc(mbuf_pool);
    if (!nm) { if (port_out < MAX_PORTS) __atomic_fetch_add(&port_tx_drop[port_out], 1, __ATOMIC_RELAXED); return; }
    if (!rte_pktmbuf_append(nm, out_len)) { rte_pktmbuf_free(nm); return; }
    rte_memcpy(rte_pktmbuf_mtod(nm, void *), out_pkt, out_len);
    tx_one(port_out, txq, nm);
}

static int mbuf_to_flat(const struct rte_mbuf *m, uint8_t *buf, int max_len) {
    int copied = 0;
    const struct rte_mbuf *seg = m;
    while (seg && copied < max_len) {
        int seglen = rte_pktmbuf_data_len(seg);
        int tocpy = (copied + seglen > max_len) ? (max_len - copied) : seglen;
        rte_memcpy(buf + copied, rte_pktmbuf_mtod(seg, const void *), tocpy);
        copied += tocpy;
        seg = seg->next;
    }
    return copied;
}

/* ── Stats JSON (UI consumes <root>/packet_broker_afxdp.stats.json) ─────── *
 * NOTE: DPDK ports are addressed by port-id, not kernel iface name. The UI
 * keys stats by iface name, so until the control plane learns the port↔name
 * mapping these appear as "portN". This is the documented UI-integration gap. */
static void write_stats_json(void) {
    char tmp[600], path[600];
    snprintf(tmp, sizeof(tmp), "%s/%s.tmp", g_rootdir, STATS_FILE);
    snprintf(path, sizeof(path), "%s/%s", g_rootdir, STATS_FILE);
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    fprintf(f, "{\"mode\":\"dpdk\",\"ts\":%ld,\"ifaces\":{", (long)time(NULL));
    int first = 1;
    for (uint16_t p = 0; p < g_nb_ports && p < MAX_PORTS; p++) {
        fprintf(f, "%s\"port%u\":{\"rx_pkts\":%lu,\"rx_bytes\":%lu,\"tx_pkts\":%lu,\"tx_bytes\":%lu,\"rx_drop\":%lu,\"tx_drop\":%lu}",
                first ? "" : ",", p,
                (unsigned long)port_rx_pkts[p], (unsigned long)port_rx_bytes[p],
                (unsigned long)port_tx_pkts[p], (unsigned long)port_tx_bytes[p],
                (unsigned long)port_rx_drop[p], (unsigned long)port_tx_drop[p]);
        first = 0;
    }
    fprintf(f, "}}\n");
    fclose(f);
    rename(tmp, path);
}

/* ── Ports manifest (id → PCI → MAC) for the UI to label rule pickers ───── *
 * DPDK NICs are vfio-bound and invisible to the kernel, so the web UI can't
 * enumerate them by name. We publish this once at startup; internal/dpdkports
 * reads it. */
static void write_ports_manifest(const uint16_t *active, int na) {
    char tmp[600], path[600];
    snprintf(tmp,  sizeof(tmp),  "%s/packet_broker_dpdk.ports.json.tmp", g_rootdir);
    snprintf(path, sizeof(path), "%s/packet_broker_dpdk.ports.json", g_rootdir);
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    fprintf(f, "{\"ports\":[");
    for (int i = 0; i < na; i++) {
        uint16_t p = active[i];
        char macs[18] = "";
        struct rte_ether_addr mac;
        if (rte_eth_macaddr_get(p, &mac) == 0)
            snprintf(macs, sizeof(macs), "%02x:%02x:%02x:%02x:%02x:%02x",
                     mac.addr_bytes[0], mac.addr_bytes[1], mac.addr_bytes[2],
                     mac.addr_bytes[3], mac.addr_bytes[4], mac.addr_bytes[5]);
        const char *pci = "";
        struct rte_eth_dev_info info;
        if (rte_eth_dev_info_get(p, &info) == 0 && info.device && info.device->name)
            pci = info.device->name;
        fprintf(f, "%s{\"id\":%u,\"pci\":\"%s\",\"mac\":\"%s\"}", i ? "," : "", p, pci, macs);
    }
    fprintf(f, "]}\n");
    fclose(f);
    rename(tmp, path);
}

/* ── Per-port packet processing (one RX queue, caller's TX queue) ───────── */

static uint16_t process_port(uint16_t portid, uint16_t txq,
                             uint8_t *flat, struct rte_mbuf **bufs) {
    uint16_t nb_rx = rte_eth_rx_burst(portid, 0, bufs, BURST_SIZE);
    if (nb_rx == 0) return 0;

    /* Read-lock the config for the whole burst so a concurrent reload on the
     * main lcore can't swap rules out mid-processing. Per-rule stats/tokens
     * are lock-free: each port is owned by exactly one worker. */
    pthread_rwlock_rdlock(&g_cfg_lock);
    for (uint16_t i = 0; i < nb_rx; i++) {
        struct rte_mbuf *m = bufs[i];
        int plen = rte_pktmbuf_pkt_len(m);
        const uint8_t *pkt;
        int need_flat = 0;
        if (rte_pktmbuf_is_contiguous(m)) {
            pkt = rte_pktmbuf_mtod(m, const uint8_t *);
        } else {
            plen = mbuf_to_flat(m, flat, SNAP_LEN); pkt = flat; need_flat = 1;
        }
        if (portid < MAX_PORTS) { port_rx_pkts[portid]++; port_rx_bytes[portid] += plen; }

        if (dedup_enabled && is_duplicate(pkt, plen)) {
            if (portid < MAX_PORTS) port_rx_drop[portid]++;
            rte_pktmbuf_free(m);
            continue;
        }

        int dpi_skip = 0;
        if (dpi_rule_count > 0) {
            const char *l7 = l7_classify(pkt, plen);
            if (strcmp(l7, "unknown") != 0) {
                for (int d = 0; d < dpi_rule_count; d++) {
                    if (strcmp(dpi_rules[d].proto, l7) != 0) continue;
                    if (strcmp(dpi_rules[d].action, "drop") == 0) { dpi_skip = 1; break; }
                    if (strcmp(dpi_rules[d].action, "forward") == 0 || strcmp(dpi_rules[d].action, "mirror") == 0) {
                        if (dpi_rules[d].output < g_nb_ports && !is_mgmt_port(dpi_rules[d].output)) {
                            if (!need_flat) { plen = mbuf_to_flat(m, flat, SNAP_LEN); pkt = flat; need_flat = 1; }
                            forward_to((uint16_t)dpi_rules[d].output, txq, VLAN_NONE, 0, 0, m, pkt, plen);
                        }
                        if (strcmp(dpi_rules[d].action, "forward") == 0) { dpi_skip = 1; break; }
                    }
                }
            }
        }
        if (dpi_skip) { rte_pktmbuf_free(m); continue; }

        for (int r = 0; r < rule_count; r++) {
            if (rules[r].port_in != portid) continue;
            int matched = match_rule(&rules[r], pkt, plen);
            if (rules[r].exclude) matched = !matched;
            if (!matched) continue;
            if (!rate_limit_check(&rules[r], plen)) continue;

            rules[r].match_count++;
            rules[r].byte_count += plen;
            if (!need_flat && (rules[r].vlan_action != VLAN_NONE ||
                (rules[r].truncate > 0 && plen > rules[r].truncate))) {
                plen = mbuf_to_flat(m, flat, SNAP_LEN); pkt = flat; need_flat = 1;
            }
            forward_to(rules[r].port_out, txq, rules[r].vlan_action, rules[r].vlan_new_id,
                       rules[r].truncate, m, pkt, plen);
        }
        rte_pktmbuf_free(m);
    }
    pthread_rwlock_unlock(&g_cfg_lock);
    return nb_rx;
}

/* ── Worker lcore: polls its assigned ports, TXes on its own queue ──────── */

typedef struct { uint16_t ports[MAX_PORTS]; int nports; uint16_t txq; } worker_arg_t;
static worker_arg_t g_wargs[MAX_PORTS];

static int worker_main(void *arg) {
    worker_arg_t *wa = (worker_arg_t *)arg;
    uint8_t flat[SNAP_LEN];
    struct rte_mbuf *bufs[BURST_SIZE];
    log_msg("Worker lcore %u: %d ports, txq %u", rte_lcore_id(), wa->nports, wa->txq);
    while (running) {
        uint16_t got = 0;
        for (int i = 0; i < wa->nports; i++)
            got += process_port(wa->ports[i], wa->txq, flat, bufs);
        if (got == 0) rte_pause();
    }
    return 0;
}

static void parse_mgmt_ports(const char *csv) {
    if (!csv || !*csv) return;
    char buf[256];
    strncpy(buf, csv, sizeof(buf)-1); buf[sizeof(buf)-1] = '\0';
    char *tok = strtok(buf, ",");
    while (tok && g_mgmt_nports < MAX_PORTS) {
        g_mgmt_ports[g_mgmt_nports++] = atoi(tok);
        tok = strtok(NULL, ",");
    }
}

/* ── Main ──────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    /* Opt-in gate: DPDK needs operator hugepage + NIC-bind setup and the UI
     * port↔name gap is open. Selecting BROKER_MODE=dpdk in the control plane
     * sets this; refuse otherwise so it's never started by accident. */
    {
        const char *ok = getenv("PB_DPDK_EXPERIMENTAL");
        if (!ok || strcmp(ok, "1") != 0) {
            fprintf(stderr,
                "packet_broker (DPDK): set PB_DPDK_EXPERIMENTAL=1 to run.\n"
                "Requires hugepages + DPDK-bound NICs; bound NICs leave the kernel\n"
                "so the web UI addresses them by port-id. Use BROKER_MODE=afxdp for\n"
                "the kernel-visible zero-copy fast path.\n");
            return 2;
        }
    }

    if (getcwd(g_rootdir, sizeof(g_rootdir)) == NULL) strcpy(g_rootdir, ".");

    log_fp = fopen(LOG_FILE, "a");
    if (!log_fp) { perror("log"); return 1; }
    write_file(STATUS_FILE, "running");
    char pidbuf[16]; snprintf(pidbuf, sizeof(pidbuf), "%d", getpid());
    write_file(PID_FILE, pidbuf);
    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);
    log_msg("Packet Broker (DPDK) starting (PID %d)", getpid());

    int ret = rte_eal_init(argc, argv);
    if (ret < 0) { log_msg("EAL init failed"); return 1; }
    argc -= ret; argv += ret;

    parse_mgmt_ports(getenv("PB_DPDK_MGMT_PORTS"));
    if (g_mgmt_nports) log_msg("Management ports excluded from rules: %d listed", g_mgmt_nports);

    g_nb_ports = rte_eth_dev_count_avail();
    if (g_nb_ports < 1) { log_msg("No DPDK ports"); return 1; }
    log_msg("DPDK: %d ports available", g_nb_ports);

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * g_nb_ports,
                                        MBUF_CACHE_SIZE, 0,
                                        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mbuf_pool) { log_msg("Cannot create mbuf pool"); return 1; }

    /* One worker per available worker lcore (each owns a subset of ports and
     * one TX queue per port). With no worker lcore (e.g. -l 0) the main lcore
     * is the sole worker. */
    unsigned wlcores[MAX_PORTS]; int nw = 0;
    unsigned lc;
    RTE_LCORE_FOREACH_WORKER(lc) { if (nw < MAX_PORTS) wlcores[nw++] = lc; }
    g_num_workers = nw > 0 ? nw : 1;
    uint16_t ntxq = (uint16_t)g_num_workers;
    log_msg("Workers: %d (tx queues per port: %u)", g_num_workers, ntxq);

    uint16_t portid;
    uint16_t active[MAX_PORTS]; int na = 0;
    RTE_ETH_FOREACH_DEV(portid) {
        if (is_mgmt_port(portid)) { log_msg("Port %d is management — not initialized", portid); continue; }
        struct rte_eth_conf port_conf;
        memset(&port_conf, 0, sizeof(port_conf));
        if (rte_eth_dev_configure(portid, 1, ntxq, &port_conf) < 0) { log_msg("Port %d configure failed", portid); continue; }
        if (rte_eth_rx_queue_setup(portid, 0, RX_RING_SIZE, rte_eth_dev_socket_id(portid), NULL, mbuf_pool) < 0) { log_msg("Port %d RX setup failed", portid); continue; }
        int txok = 1;
        for (uint16_t q = 0; q < ntxq; q++)
            if (rte_eth_tx_queue_setup(portid, q, TX_RING_SIZE, rte_eth_dev_socket_id(portid), NULL) < 0) { txok = 0; break; }
        if (!txok) { log_msg("Port %d TX setup failed", portid); continue; }
        if (rte_eth_dev_start(portid) < 0) { log_msg("Port %d start failed", portid); continue; }
        rte_eth_promiscuous_enable(portid);
        log_msg("Port %d initialized (promiscuous)", portid);
        if (na < MAX_PORTS) active[na++] = portid;
    }

    load_rules();
    load_dedup_config();
    load_dpi_config();
    write_ports_manifest(active, na);
    log_msg("Broker running: %d active ports, %d rules", na, rule_count);

    /* Distribute active ports round-robin across workers. */
    for (int i = 0; i < g_num_workers; i++) { g_wargs[i].nports = 0; g_wargs[i].txq = (uint16_t)i; }
    for (int i = 0; i < na; i++) {
        worker_arg_t *w = &g_wargs[i % g_num_workers];
        if (w->nports < MAX_PORTS) w->ports[w->nports++] = active[i];
    }

    time_t last_stats = 0;
    if (nw > 0) {
        for (int i = 0; i < nw; i++)
            rte_eal_remote_launch(worker_main, &g_wargs[i], wlcores[i]);
        /* Main lcore handles config reload + stats while workers move packets. */
        while (running) {
            check_for_updates();
            time_t tnow = time(NULL);
            if (tnow != last_stats) { write_stats_json(); last_stats = tnow; }
            usleep(200000);
        }
        rte_eal_mp_wait_lcore();
    } else {
        /* Single-lcore fallback: main does packets + housekeeping. */
        uint8_t flat[SNAP_LEN];
        struct rte_mbuf *bufs[BURST_SIZE];
        uint64_t loop = 0;
        while (running) {
            for (int i = 0; i < g_wargs[0].nports; i++)
                process_port(g_wargs[0].ports[i], 0, flat, bufs);
            if ((++loop & 0xFFFF) == 0) check_for_updates();
            time_t tnow = time(NULL);
            if (tnow != last_stats) { write_stats_json(); last_stats = tnow; }
        }
    }

    log_msg("Shutting down...");
    free_bpf_handles();
    RTE_ETH_FOREACH_DEV(portid) {
        if (is_mgmt_port(portid)) continue;
        rte_eth_dev_stop(portid);
        rte_eth_dev_close(portid);
    }
    write_file(STATUS_FILE, "stopped");
    log_msg("Broker stopped");
    fclose(log_fp);
    rte_eal_cleanup();
    return 0;
}
