/*
 * Packet Broker — libpcap edition
 *
 * Reads rules from rules.conf, captures packets on input interfaces,
 * applies filters (IP, port, protocol, VLAN, TCP flags, string match),
 * performs VLAN manipulation (add/remove/change) and truncation,
 * then forwards to output interfaces.
 *
 * Extended CSV format (fields 1–8 required, 9–18 optional):
 *   interface_in, tcp_flags, dest_port, protocol, vlan_id, string_match,
 *   exclude, interface_out, enabled, priority, vlan_action, vlan_new_id,
 *   truncate, src_ip, dst_ip, src_mac, dst_mac, bpf_filter
 *
 * Build:
 *   gcc -O2 -o packet_broker packet_broker_libpcap.c -lpcap -lpthread
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

/* ── Constants ─────────────────────────────────────────────────────────── */

#define MAX_RULES       256
#define MAX_INTERFACES  48
#define SNAP_LEN        65535
#define LINE_LEN        1024
#define FIELD_LEN       64
#undef BPF_LEN
#define BPF_LEN         256
#define RULE_FILE       "rules.conf"
#define LOG_FILE        "packet_broker.log"
#define STATUS_FILE     "packet_broker.status"
#define PID_FILE        "packet_broker.pid"
#define STATS_JSON      "packet_broker.stats.json" /* dpstats-compatible per-iface counters (recv/drop) */
#define STATS_INTERVAL  5     /* seconds between stats log */
#define ETHERTYPE_VLAN  0x8100

/* ── VLAN actions ──────────────────────────────────────────────────────── */

enum vlan_action {
    VLAN_NONE   = 0,
    VLAN_ADD    = 1,
    VLAN_REMOVE = 2,
    VLAN_CHANGE = 3
};

/* ── Rule structure ────────────────────────────────────────────────────── */

typedef struct {
    /* Core fields (legacy 8-field format) */
    char     iface_in[FIELD_LEN];
    char     tcp_flags[FIELD_LEN];
    int      dest_port;
    int      src_port;
    char     protocol[FIELD_LEN];
    int      vlan_id;          /* match VLAN, 0 = any */
    char     string_match[FIELD_LEN];
    int      exclude;          /* 1 = invert match */
    char     iface_out[FIELD_LEN];

    /* Extended fields */
    int      enabled;          /* 1 = active, 0 = skip */
    int      priority;         /* lower = higher priority */

    /* VLAN manipulation */
    int      vlan_action;      /* enum vlan_action */
    int      vlan_new_id;      /* target VLAN for add/change */

    /* Truncation */
    int      truncate;         /* max bytes to forward, 0 = full */

    /* Extended filters */
    uint32_t src_ip;           /* network byte order, 0 = any */
    uint32_t src_mask;         /* CIDR mask */
    uint32_t dst_ip;
    uint32_t dst_mask;
    uint8_t  src_mac[6];
    uint8_t  dst_mac[6];
    int      has_src_mac;
    int      has_dst_mac;
    char     bpf_filter[BPF_LEN];
    struct bpf_program bpf_prog;    /* compiled BPF program, valid iff has_bpf */
    int      has_bpf;               /* 1 = bpf_prog compiled and must be applied */

    /* Bandwidth throttling (token bucket) */
    uint64_t rate_limit_bps;    /* bytes/sec, 0 = unlimited */
    uint64_t rate_limit_pps;    /* packets/sec, 0 = unlimited */
    uint64_t tokens_bytes;      /* current byte tokens */
    uint64_t tokens_pkts;       /* current pkt tokens */
    struct timespec last_refill;

    /* Stats */
    uint64_t match_count;
    uint64_t byte_count;
    uint64_t drop_count;        /* dropped by rate limiter */
} rule_t;

/* Forward declarations */
static void log_msg(const char *fmt, ...);
static pcap_t *get_output_handle(const char *iface);

/* ── L7 Protocol Detection (Application Intelligence) ──────────────────── */

#define DPI_STATS_SIZE 64
#define DPI_CONF_FILE  "dpi.conf"

typedef struct {
    char     proto[32];     /* protocol ID string */
    char     action[16];    /* "forward","mirror","drop","alert" */
    char     output[FIELD_LEN];
} dpi_rule_t;

static dpi_rule_t dpi_rules[DPI_STATS_SIZE];
static int        dpi_rule_count = 0;

typedef struct {
    char     proto[32];
    uint64_t count;
    uint64_t bytes;
} dpi_stat_t;

static dpi_stat_t dpi_stats[DPI_STATS_SIZE];
static int        dpi_stat_count = 0;
static pthread_mutex_t dpi_lock = PTHREAD_MUTEX_INITIALIZER;

static void dpi_record(const char *proto, int pkt_len) {
    pthread_mutex_lock(&dpi_lock);
    for (int i = 0; i < dpi_stat_count; i++) {
        if (strcmp(dpi_stats[i].proto, proto) == 0) {
            dpi_stats[i].count++;
            dpi_stats[i].bytes += pkt_len;
            pthread_mutex_unlock(&dpi_lock);
            return;
        }
    }
    if (dpi_stat_count < DPI_STATS_SIZE) {
        strncpy(dpi_stats[dpi_stat_count].proto, proto, 31);
        dpi_stats[dpi_stat_count].count = 1;
        dpi_stats[dpi_stat_count].bytes = pkt_len;
        dpi_stat_count++;
    }
    pthread_mutex_unlock(&dpi_lock);
}

/*
 * detect_l7_protocol — identify application protocol from payload.
 *
 * Checks payload signatures for:
 *   IT: HTTP, TLS (ClientHello → SNI), SSH, DNS, SMTP, FTP, MQTT, RDP, SIP, SMB
 *   OT: Modbus/TCP, DNP3, S7comm, EtherNet/IP, BACnet, OPC-UA, IEC 104,
 *       FINS, HART-IP, PROFINET
 *
 * Returns protocol ID string or "unknown".
 */
static const char *detect_l7_protocol(const uint8_t *payload, int len,
                                       int ip_proto, int src_port, int dst_port) {
    if (len < 2) return "unknown";

    /* ── Port-based fast path for well-known services ── */

    /* DNS (port 53) */
    if ((dst_port == 53 || src_port == 53) && ip_proto == IPPROTO_UDP && len >= 12)
        return "dns";

    /* NTP (port 123) */
    if ((dst_port == 123 || src_port == 123) && ip_proto == IPPROTO_UDP)
        return "ntp";

    /* SNMP (port 161/162) */
    if ((dst_port == 161 || dst_port == 162 || src_port == 161) && ip_proto == IPPROTO_UDP)
        return "snmp";

    /* RDP (port 3389) */
    if (dst_port == 3389 || src_port == 3389)
        return "rdp";

    /* ── OT/ICS Protocol Detection (by port + signature) ── */

    /* Modbus/TCP (port 502) — header: TxID(2) + ProtoID(2, must be 0x0000) + Len(2) + UnitID(1) */
    if ((dst_port == 502 || src_port == 502) && len >= 7) {
        if (payload[2] == 0x00 && payload[3] == 0x00) /* Protocol ID = 0 */
            return "modbus";
    }

    /* DNP3 (port 20000) — start bytes: 0x0564 */
    if ((dst_port == 20000 || src_port == 20000) && len >= 2) {
        if (payload[0] == 0x05 && payload[1] == 0x64)
            return "dnp3";
    }

    /* S7comm / Siemens (port 102) — TPKT header: 0x03 0x00 */
    if ((dst_port == 102 || src_port == 102) && len >= 4) {
        if (payload[0] == 0x03 && payload[1] == 0x00)
            return "s7comm";
    }

    /* EtherNet/IP (port 44818) — encapsulation header */
    if ((dst_port == 44818 || src_port == 44818 || dst_port == 2222 || src_port == 2222) && len >= 4)
        return "enip";

    /* BACnet (port 47808) */
    if ((dst_port == 47808 || src_port == 47808) && ip_proto == IPPROTO_UDP && len >= 4) {
        if (payload[0] == 0x81) /* BACnet/IP BVLC type */
            return "bacnet";
    }

    /* OPC-UA (port 4840) — "OPN" or message header */
    if ((dst_port == 4840 || src_port == 4840) && len >= 4) {
        if (memcmp(payload, "OPN", 3) == 0 || memcmp(payload, "HEL", 3) == 0 ||
            memcmp(payload, "ACK", 3) == 0 || memcmp(payload, "MSG", 3) == 0)
            return "opcua";
    }

    /* IEC 60870-5-104 (port 2404) — start byte 0x68 */
    if ((dst_port == 2404 || src_port == 2404) && len >= 2) {
        if (payload[0] == 0x68)
            return "iec104";
    }

    /* FINS / Omron (port 9600) */
    if ((dst_port == 9600 || src_port == 9600) && len >= 4) {
        if (memcmp(payload, "FINS", 4) == 0 || payload[0] == 0x80)
            return "fins";
    }

    /* HART-IP (port 5094) */
    if ((dst_port == 5094 || src_port == 5094) && len >= 4)
        return "hartip";

    /* ── Payload signature detection (IT protocols) ── */

    /* HTTP — "GET ", "POST ", "PUT ", "HEAD ", "HTTP/" */
    if (len >= 4) {
        if (memcmp(payload, "GET ", 4) == 0 || memcmp(payload, "POST", 4) == 0 ||
            memcmp(payload, "PUT ", 4) == 0 || memcmp(payload, "HEAD", 4) == 0 ||
            memcmp(payload, "HTTP", 4) == 0 || memcmp(payload, "DELE", 4) == 0 ||
            memcmp(payload, "PATC", 4) == 0 || memcmp(payload, "OPTI", 4) == 0)
            return "http";
    }

    /* TLS ClientHello — ContentType=0x16, Version=0x0301-0x0303, HandshakeType=0x01 */
    if (len >= 6 && payload[0] == 0x16) {
        if ((payload[1] == 0x03) && (payload[2] >= 0x00 && payload[2] <= 0x04)) {
            if (len >= 6 && payload[5] == 0x01) /* Client Hello */
                return "tls";
            return "tls";
        }
    }

    /* SSH — "SSH-" banner */
    if (len >= 4 && memcmp(payload, "SSH-", 4) == 0)
        return "ssh";

    /* SMTP — "220 ", "EHLO", "HELO", "MAIL" */
    if (len >= 4) {
        if (memcmp(payload, "220 ", 4) == 0 || memcmp(payload, "EHLO", 4) == 0 ||
            memcmp(payload, "HELO", 4) == 0 || memcmp(payload, "MAIL", 4) == 0)
            return "smtp";
    }

    /* FTP — "220-", "USER", "PASS", "230 " */
    if (len >= 4) {
        if ((memcmp(payload, "220-", 4) == 0 || memcmp(payload, "220 ", 4) == 0) &&
            (dst_port == 21 || src_port == 21))
            return "ftp";
        if (memcmp(payload, "USER", 4) == 0 || memcmp(payload, "PASS", 4) == 0)
            if (dst_port == 21) return "ftp";
    }

    /* MQTT — Connect: first byte upper nibble = 0x10 (CONNECT), 0x20 (CONNACK) */
    if (len >= 2 && ((payload[0] & 0xF0) == 0x10 || (payload[0] & 0xF0) == 0x20)) {
        if (dst_port == 1883 || dst_port == 8883 || src_port == 1883)
            return "mqtt";
    }

    /* SIP — "SIP/2.0" or "INVITE" or "REGISTER" */
    if (len >= 7 && (memcmp(payload, "SIP/2.0", 7) == 0 || memcmp(payload, "INVITE ", 7) == 0))
        return "sip";

    /* SMB — NetBIOS session + SMB header "\xffSMB" or "\xfeSMB" (SMB2) */
    if (len >= 8 && (dst_port == 445 || src_port == 445)) {
        if (payload[4] == 0xFF && payload[5] == 'S' && payload[6] == 'M' && payload[7] == 'B')
            return "smb";
        if (payload[4] == 0xFE && payload[5] == 'S' && payload[6] == 'M' && payload[7] == 'B')
            return "smb";
    }

    /* LDAP (port 389/636) — BER encoded, first byte 0x30 (SEQUENCE) */
    if ((dst_port == 389 || dst_port == 636 || src_port == 389) && len >= 2) {
        if (payload[0] == 0x30)
            return "ldap";
    }

    return "unknown";
}

static void load_dpi_config(void) {
    /* Stage into a local array first, then publish under dpi_lock so the
     * capture threads (which snapshot dpi_rules under the same lock) never
     * observe a half-written entry — a torn strncpy could leave proto[]
     * non-NUL-terminated and make the strcmp in packet_handler walk off
     * the buffer. */
    dpi_rule_t staged[DPI_STATS_SIZE];
    int count = 0;
    FILE *f = fopen(DPI_CONF_FILE, "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f) && count < DPI_STATS_SIZE) {
            char proto[32], action[16], output[FIELD_LEN];
            if (sscanf(line, "%31[^,],%15[^,],%63s", proto, action, output) >= 2) {
                memset(&staged[count], 0, sizeof(staged[count]));
                strncpy(staged[count].proto, proto, sizeof(staged[count].proto) - 1);
                strncpy(staged[count].action, action, sizeof(staged[count].action) - 1);
                strncpy(staged[count].output, output, sizeof(staged[count].output) - 1);
                count++;
            }
        }
        fclose(f);
    }
    pthread_mutex_lock(&dpi_lock);
    if (count > 0) memcpy(dpi_rules, staged, sizeof(dpi_rule_t) * (size_t)count);
    dpi_rule_count = count;
    pthread_mutex_unlock(&dpi_lock);
    if (count > 0) log_msg("Loaded %d DPI rules", count);
}

/* ── Deduplication ─────────────────────────────────────────────────────── */

#define DEDUP_TABLE_SIZE 65536
#define DEDUP_CONF_FILE  "dedup.conf"

typedef struct {
    uint32_t        hash;
    struct timespec seen;
} dedup_entry_t;

static dedup_entry_t dedup_table[DEDUP_TABLE_SIZE];
static int           dedup_enabled = 0;
static int           dedup_window_us = 100000; /* 100ms */
static int           dedup_hash_bytes = 128;
static pthread_mutex_t dedup_lock = PTHREAD_MUTEX_INITIALIZER;

/* Simple CRC32 (no zlib dependency) */
static uint32_t crc32_calc(const uint8_t *data, int len) {
    uint32_t crc = 0xFFFFFFFF;
    for (int i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
    }
    return ~crc;
}

static int is_duplicate(const u_char *pkt, int len) {
    if (!dedup_enabled) return 0;

    int hash_len = len < dedup_hash_bytes ? len : dedup_hash_bytes;
    uint32_t h = crc32_calc(pkt, hash_len);
    int idx = h & (DEDUP_TABLE_SIZE - 1);

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    pthread_mutex_lock(&dedup_lock);
    dedup_entry_t *e = &dedup_table[idx];

    /* Check if same hash within window */
    if (e->hash == h) {
        long elapsed_us = (now.tv_sec - e->seen.tv_sec) * 1000000L +
                          (now.tv_nsec - e->seen.tv_nsec) / 1000L;
        if (elapsed_us < dedup_window_us) {
            pthread_mutex_unlock(&dedup_lock);
            return 1; /* duplicate */
        }
    }
    e->hash = h;
    e->seen = now;
    pthread_mutex_unlock(&dedup_lock);
    return 0;
}

static void load_dedup_config(void) {
    FILE *f = fopen(DEDUP_CONF_FILE, "r");
    if (!f) { dedup_enabled = 0; return; }
    char line[256];
    int any_enabled = 0;
    while (fgets(line, sizeof(line), f)) {
        /* Format: port,enabled,window_ms,hash_bytes */
        char port[FIELD_LEN]; int en, wms, hb;
        /* %63[^,] caps the port-name capture at FIELD_LEN-1 chars and avoids
         * a stack-buffer overflow if rules.conf is hand-edited with a long
         * port field (defense-in-depth — Go UI normally writes sane names). */
        if (sscanf(line, "%63[^,],%d,%d,%d", port, &en, &wms, &hb) >= 2) {
            if (en) {
                any_enabled = 1;
                if (wms > 0) dedup_window_us = wms * 1000;
                if (hb > 0) dedup_hash_bytes = hb;
            }
        }
    }
    fclose(f);
    dedup_enabled = any_enabled;
    if (any_enabled) log_msg("Dedup enabled: window=%dus hash=%dB", dedup_window_us, dedup_hash_bytes);
}

/* ── Globals ───────────────────────────────────────────────────────────── */

static rule_t       rules[MAX_RULES];
static int          rule_count = 0;
static time_t       last_modified = 0;
static volatile int running = 1;
static FILE        *log_fp = NULL;
static pthread_mutex_t rules_lock = PTHREAD_MUTEX_INITIALIZER;

/* Output handle cache */
typedef struct {
    char    name[FIELD_LEN];
    pcap_t *handle;
} iface_cache_t;

static iface_cache_t out_cache[MAX_INTERFACES];
static int           out_cache_count = 0;
static pthread_mutex_t cache_lock = PTHREAD_MUTEX_INITIALIZER;
/* Serializes pcap_inject on a shared output handle: multiple capture threads
 * (different input ifaces) forward to the same cached pcap_t, and pcap_inject
 * is not thread-safe on one handle. The DPI path holds no other lock, so this
 * dedicated mutex covers both inject sites. */
static pthread_mutex_t inject_lock = PTHREAD_MUTEX_INITIALIZER;

/* ── Logging ───────────────────────────────────────────────────────────── */

static void log_msg(const char *fmt, ...) {
    if (!log_fp) return;
    va_list ap;
    va_start(ap, fmt);
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv); /* reentrant: log_msg is called from N threads */
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

/* ── Signal handler ────────────────────────────────────────────────────── */

static void handle_signal(int sig) {
    (void)sig;
    running = 0;
}

/* ── Parsing helpers ───────────────────────────────────────────────────── */

static void trim(char *s) {
    /* trim leading */
    char *p = s;
    while (*p == ' ' || *p == '\t') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    /* trim trailing */
    int len = strlen(s);
    while (len > 0 && (s[len-1] == ' ' || s[len-1] == '\t' ||
                       s[len-1] == '\r' || s[len-1] == '\n'))
        s[--len] = '\0';
}

/* Parse "192.168.1.0/24" into ip + mask */
static int parse_cidr(const char *s, uint32_t *ip, uint32_t *mask) {
    if (!s || !*s || strcmp(s, "0") == 0) {
        *ip = 0; *mask = 0;
        return 0;
    }
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

/* Parse "AA:BB:CC:DD:EE:FF" */
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

/* ── Load rules ────────────────────────────────────────────────────────── */

static void load_rules(void) {
    FILE *f = fopen(RULE_FILE, "r");
    if (!f) { log_msg("Cannot open %s", RULE_FILE); return; }

    rule_t new_rules[MAX_RULES];
    int count = 0;
    char line[LINE_LEN];

    while (fgets(line, sizeof(line), f) && count < MAX_RULES) {
        trim(line);
        if (line[0] == '\0' || line[0] == '#') continue;

        /* Tokenize up to 22 fields, PRESERVING empty fields. strtok() collapses
         * consecutive commas, which misaligns the columns whenever an optional
         * field (e.g. string_match) is empty — exactly what the Go control plane
         * writes. Manual comma-split matches Go's strings.Split round-trip. */
        char *fields[22];
        int nf = 0;
        fields[nf++] = line;
        for (char *p = line; nf < 22 && (p = strchr(p, ',')) != NULL; ) {
            *p++ = '\0';
            fields[nf++] = p;
        }
        for (int fi = 0; fi < nf; fi++) trim(fields[fi]);
        if (nf < 8) continue; /* minimum: 8 core fields */

        rule_t *r = &new_rules[count];
        memset(r, 0, sizeof(rule_t));

        /* Core fields */
        strncpy(r->iface_in,     fields[0], FIELD_LEN-1);
        strncpy(r->tcp_flags,    fields[1], FIELD_LEN-1);
        r->dest_port = atoi(fields[2]);
        strncpy(r->protocol,     fields[3], FIELD_LEN-1);
        r->vlan_id = atoi(fields[4]);
        strncpy(r->string_match, fields[5], FIELD_LEN-1);
        r->exclude = atoi(fields[6]);
        strncpy(r->iface_out,    fields[7], FIELD_LEN-1);

        /* Extended fields (defaults for backward compat) */
        r->enabled      = nf > 8  ? atoi(fields[8])  : 1;
        r->priority     = nf > 9  ? atoi(fields[9])  : count;
        r->vlan_action  = nf > 10 ? parse_vlan_action(fields[10]) : VLAN_NONE;
        r->vlan_new_id  = nf > 11 ? atoi(fields[11]) : 0;
        r->truncate     = nf > 12 ? atoi(fields[12]) : 0;

        if (nf > 13) parse_cidr(fields[13], &r->src_ip, &r->src_mask);
        if (nf > 14) parse_cidr(fields[14], &r->dst_ip, &r->dst_mask);
        if (nf > 15) r->has_src_mac = parse_mac(fields[15], r->src_mac);
        if (nf > 16) r->has_dst_mac = parse_mac(fields[16], r->dst_mac);
        if (nf > 17) strncpy(r->bpf_filter, fields[17], BPF_LEN-1);

        /* Rate limiting (fields 19-20, 0-indexed 18-19) */
        if (nf > 18) {
            int mbps = atoi(fields[18]);
            r->rate_limit_bps = (uint64_t)mbps * 125000ULL; /* Mbps → bytes/sec */
        }
        if (nf > 19) r->rate_limit_pps = (uint64_t)atoi(fields[19]);
        /* Initialize token bucket */
        if (r->rate_limit_bps > 0) r->tokens_bytes = r->rate_limit_bps;
        if (r->rate_limit_pps > 0) r->tokens_pkts = r->rate_limit_pps;
        clock_gettime(CLOCK_MONOTONIC, &r->last_refill);

        /* Skip disabled rules */
        if (!r->enabled) continue;

        /* Validate */
        if (r->iface_in[0] == '\0' || r->iface_out[0] == '\0') continue;

        /* Compile the BPF filter (only for validated, enabled rules so a
         * skipped/disabled slot never leaks a malloc'd program). pcap_compile
         * needs a handle only for its DLT/snaplen — a dead handle suffices and
         * avoids touching a live capture. */
        if (r->bpf_filter[0] != '\0' && strcmp(r->bpf_filter, "0") != 0) {
            pcap_t *dead = pcap_open_dead(DLT_EN10MB, SNAP_LEN);
            if (dead) {
                if (pcap_compile(dead, &r->bpf_prog, r->bpf_filter, 1,
                                 PCAP_NETMASK_UNKNOWN) == 0)
                    r->has_bpf = 1;
                else
                    log_msg("BPF compile failed for '%s': %s",
                            r->bpf_filter, pcap_geterr(dead));
                pcap_close(dead);
            }
        }

        count++;
    }
    fclose(f);

    /* Sort by priority */
    for (int i = 0; i < count - 1; i++)
        for (int j = i + 1; j < count; j++)
            if (new_rules[j].priority < new_rules[i].priority) {
                rule_t tmp = new_rules[i];
                new_rules[i] = new_rules[j];
                new_rules[j] = tmp;
            }

    pthread_mutex_lock(&rules_lock);
    /* Release the previous generation's compiled BPF programs before they are
     * overwritten — pcap_compile malloc's bf_insns and the wholesale memcpy
     * would otherwise leak it on every reload. Safe under rules_lock: capture
     * threads only read rules[] while holding the same lock. */
    for (int i = 0; i < rule_count; i++)
        if (rules[i].has_bpf) pcap_freecode(&rules[i].bpf_prog);
    memcpy(rules, new_rules, sizeof(rule_t) * count);
    rule_count = count;
    pthread_mutex_unlock(&rules_lock);

    log_msg("Loaded %d rules from %s", count, RULE_FILE);
}

static void check_for_updates(void) {
    struct stat st;
    if (stat(RULE_FILE, &st) == 0 && st.st_mtime != last_modified) {
        last_modified = st.st_mtime;
        log_msg("Rules file changed, reloading...");
        load_rules();
        load_dedup_config();
        load_dpi_config();
    }
}

/* ── Output handle cache ───────────────────────────────────────────────── */

static pcap_t *get_output_handle(const char *iface) {
    pthread_mutex_lock(&cache_lock);
    for (int i = 0; i < out_cache_count; i++) {
        if (strcmp(out_cache[i].name, iface) == 0) {
            pcap_t *h = out_cache[i].handle;
            pthread_mutex_unlock(&cache_lock);
            return h;
        }
    }
    /* Open new */
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *h = pcap_open_live(iface, SNAP_LEN, 0, 0, errbuf);
    if (!h) {
        log_msg("Cannot open output %s: %s", iface, errbuf);
        pthread_mutex_unlock(&cache_lock);
        return NULL;
    }
    if (out_cache_count < MAX_INTERFACES) {
        strncpy(out_cache[out_cache_count].name, iface, FIELD_LEN-1);
        out_cache[out_cache_count].handle = h;
        out_cache_count++;
    } else {
        /* Cache full: closing here avoids an unbounded handle/fd leak when
         * more than MAX_INTERFACES distinct outputs are configured. Only
         * cached handles are closed at shutdown, so an uncached one would
         * leak on every packet. */
        log_msg("Output handle cache full (%d); refusing %s", MAX_INTERFACES, iface);
        pcap_close(h);
        h = NULL;
    }
    pthread_mutex_unlock(&cache_lock);
    return h;
}

/* ── VLAN manipulation ─────────────────────────────────────────────────── */

/*
 * 802.1Q frame layout:
 *   [dst MAC 6][src MAC 6][0x8100 2][TCI 2][EtherType 2][payload...]
 *
 * Regular frame:
 *   [dst MAC 6][src MAC 6][EtherType 2][payload...]
 */

/* Per-packet entry points bounds-check `len` before touching headers.
 * Sub-14-byte (sub-Ethernet) frames are rejected outright; VLAN paths
 * require sub-18. This closes the OOB-read/write family the audit
 * flagged — without these guards, a sub-12-byte frame routed through a
 * VLAN_ADD rule yielded memcpy(_, _, len-12) with len-12 ≈ 4 GiB → RCE
 * primitive on a daemon that runs as root. */

#define ETH_HDR_MIN  14
#define VLAN_HDR_MIN 18

/* Returns 1 if packet has a VLAN tag. Returns 0 on runt frames. */
static int has_vlan_tag(const u_char *pkt, int len) {
    if (len < ETH_HDR_MIN) return 0;
    uint16_t ethertype;
    memcpy(&ethertype, pkt + 12, 2);
    return ntohs(ethertype) == ETHERTYPE_VLAN;
}

/* Extract VLAN ID from tagged frame. Returns 0 if not VLAN-shaped. */
static int get_vlan_id(const u_char *pkt, int len) {
    if (len < VLAN_HDR_MIN) return 0;
    uint16_t tci;
    memcpy(&tci, pkt + 14, 2);
    return ntohs(tci) & 0x0FFF;
}

/* Add VLAN tag: insert 4 bytes (0x8100 + TCI) after src MAC.
 * Returns new packet length. Runt frame or undersized out_buf → no-op. */
static int vlan_tag_add(const u_char *pkt, int len, int vlan_id,
                        u_char *out_buf, int out_buf_size) {
    if (len < ETH_HDR_MIN)      return len;
    if (len + 4 > out_buf_size) return len;
    memcpy(out_buf, pkt, 12);
    out_buf[12] = 0x81; out_buf[13] = 0x00;
    uint16_t tci = htons((uint16_t)(vlan_id & 0x0FFF));
    memcpy(out_buf + 14, &tci, 2);
    memcpy(out_buf + 16, pkt + 12, (size_t)(len - 12));
    return len + 4;
}

/* Strip 802.1Q tag if present. Untagged/runt frames copied as-is. */
static int vlan_tag_remove(const u_char *pkt, int len,
                           u_char *out_buf, int out_buf_size) {
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
static int vlan_tag_change(const u_char *pkt, int len, int new_vlan_id,
                           u_char *out_buf, int out_buf_size) {
    if (len < ETH_HDR_MIN) return len;
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

static int match_rule(const rule_t *r, const u_char *pkt, int len) {
    /* Reject runt frames before any header walking. */
    if (len < ETH_HDR_MIN) return 0;

    /* BPF filter: a compiled tcpdump-syntax expression is the most expressive
     * selector and overrides nothing — it is an additional AND condition. The
     * frame must satisfy it on top of the structured fields below.
     *
     * SPAN/mirror sources (e.g. VMware VGT trunks) deliver 802.1Q-tagged
     * frames, and a plain user filter like "tcp port 443" assumes untagged
     * Ethernet — it would never match through the tag (ethertype sits at
     * offset 16, not 12). Present a de-tagged copy to the filter so the
     * operator's expression works regardless of how the mirror tags traffic,
     * mirroring how the structured fields above already skip the tag. */
    if (r->has_bpf) {
        struct pcap_pkthdr ph;
        const u_char *fpkt = pkt;
        int flen = len;
        u_char detag[SNAP_LEN];
        uint16_t et0;
        memcpy(&et0, pkt + 12, 2);
        if (ntohs(et0) == ETHERTYPE_VLAN && len >= VLAN_HDR_MIN) {
            int n = len - 4;
            if (n > (int)sizeof(detag)) n = sizeof(detag);
            memcpy(detag, pkt, 12);                 /* dst + src MAC */
            memcpy(detag + 12, pkt + 16, (size_t)(n - 12)); /* inner ethertype + payload */
            fpkt = detag;
            flen = n;
        }
        ph.caplen = (bpf_u_int32)flen;
        ph.len = (bpf_u_int32)flen;
        if (pcap_offline_filter(&r->bpf_prog, &ph, fpkt) == 0) return 0;
    }

    /* Determine ethernet header size (14 or 18 with VLAN) */
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
    if (r->has_dst_mac && memcmp(pkt, r->dst_mac, 6) != 0) return 0;
    if (r->has_src_mac && memcmp(pkt + 6, r->src_mac, 6) != 0) return 0;

    /* VLAN ID filter */
    if (r->vlan_id != 0) {
        if (!has_vlan_tag(pkt, len)) return 0;
        if (get_vlan_id(pkt, len) != r->vlan_id) return 0;
    }

    /* Need IP header for remaining checks */
    if (ethertype != ETHERTYPE_IP) {
        /* Non-IP packet: skip IP/port/protocol checks */
        /* But if rule requires specific protocol/port, no match */
        if (r->dest_port != 0) return 0;
        if (r->protocol[0] != '\0' && strcmp(r->protocol, "0") != 0) return 0;
        if (r->src_ip != 0 || r->dst_ip != 0) return 0;
        if (r->tcp_flags[0] != '\0' && strcmp(r->tcp_flags, "0") != 0) return 0;
        return 1; /* Match: no IP-level filters set */
    }

    if (len < eth_hdr_len + 20) return 0; /* too short for IP */

    const struct ip *iph = (const struct ip *)(pkt + eth_hdr_len);
    int ip_hdr_len = iph->ip_hl * 4;
    if (ip_hdr_len < 20) return 0;

    /* Source IP filter (CIDR) */
    if (r->src_ip != 0) {
        if ((iph->ip_src.s_addr & r->src_mask) != (r->src_ip & r->src_mask))
            return 0;
    }

    /* Dest IP filter (CIDR) */
    if (r->dst_ip != 0) {
        if ((iph->ip_dst.s_addr & r->dst_mask) != (r->dst_ip & r->dst_mask))
            return 0;
    }

    /* Protocol filter */
    if (r->protocol[0] != '\0' && strcmp(r->protocol, "0") != 0) {
        if (strcasecmp(r->protocol, "TCP") == 0  && iph->ip_p != IPPROTO_TCP)  return 0;
        if (strcasecmp(r->protocol, "UDP") == 0  && iph->ip_p != IPPROTO_UDP)  return 0;
        if (strcasecmp(r->protocol, "ICMP") == 0 && iph->ip_p != IPPROTO_ICMP) return 0;
    }

    /* Port and TCP flags: need transport header */
    if (iph->ip_p == IPPROTO_TCP && len >= eth_hdr_len + ip_hdr_len + 20) {
        const struct tcphdr *tcp = (const struct tcphdr *)(pkt + eth_hdr_len + ip_hdr_len);

        /* Dest port */
        if (r->dest_port != 0 && ntohs(tcp->th_dport) != r->dest_port) return 0;

        /* TCP flags */
        if (r->tcp_flags[0] != '\0' && strcmp(r->tcp_flags, "0") != 0) {
            uint8_t flags = tcp->th_flags;
            const char *f = r->tcp_flags;
            while (*f) {
                switch (*f) {
                    case 'S': if (!(flags & TH_SYN))  return 0; break;
                    case 'A': if (!(flags & TH_ACK))  return 0; break;
                    case 'F': if (!(flags & TH_FIN))  return 0; break;
                    case 'R': if (!(flags & TH_RST))  return 0; break;
                    case 'P': if (!(flags & TH_PUSH)) return 0; break;
                    case 'U': if (!(flags & TH_URG))  return 0; break;
                }
                f++;
            }
        }

        /* String match in TCP payload */
        if (r->string_match[0] != '\0' && strcmp(r->string_match, "0") != 0) {
            int tcp_hdr_len = tcp->th_off * 4;
            int payload_off = eth_hdr_len + ip_hdr_len + tcp_hdr_len;
            int payload_len = len - payload_off;
            if (payload_len <= 0) return 0;
            if (!memmem(pkt + payload_off, payload_len,
                        r->string_match, strlen(r->string_match)))
                return 0;
        }
    } else if (iph->ip_p == IPPROTO_UDP && len >= eth_hdr_len + ip_hdr_len + 8) {
        const struct udphdr *udp = (const struct udphdr *)(pkt + eth_hdr_len + ip_hdr_len);

        /* Dest port (UDP) */
        if (r->dest_port != 0 && ntohs(udp->uh_dport) != r->dest_port) return 0;

        /* String match in UDP payload */
        if (r->string_match[0] != '\0' && strcmp(r->string_match, "0") != 0) {
            int payload_off = eth_hdr_len + ip_hdr_len + 8;
            int payload_len = len - payload_off;
            if (payload_len <= 0) return 0;
            if (!memmem(pkt + payload_off, payload_len,
                        r->string_match, strlen(r->string_match)))
                return 0;
        }

        /* TCP flags on UDP → no match */
        if (r->tcp_flags[0] != '\0' && strcmp(r->tcp_flags, "0") != 0) return 0;
    } else {
        /* Other protocols (ICMP etc.) */
        if (r->dest_port != 0) return 0;
        if (r->tcp_flags[0] != '\0' && strcmp(r->tcp_flags, "0") != 0) return 0;

        if (r->string_match[0] != '\0' && strcmp(r->string_match, "0") != 0) {
            int payload_off = eth_hdr_len + ip_hdr_len;
            int payload_len = len - payload_off;
            if (payload_len <= 0) return 0;
            if (!memmem(pkt + payload_off, payload_len,
                        r->string_match, strlen(r->string_match)))
                return 0;
        }
    }

    return 1;
}

/* ── Forward packet ────────────────────────────────────────────────────── */

/* Token bucket rate limiter. Returns 1 if packet should be forwarded, 0 if dropped. */
static int rate_limit_check(rule_t *r, int pkt_bytes) {
    if (r->rate_limit_bps == 0 && r->rate_limit_pps == 0) return 1; /* no limit */

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    /* Refill tokens based on elapsed time */
    double elapsed = (now.tv_sec - r->last_refill.tv_sec) +
                     (now.tv_nsec - r->last_refill.tv_nsec) / 1e9;
    if (elapsed > 0) {
        if (r->rate_limit_bps > 0) {
            r->tokens_bytes += (uint64_t)(elapsed * r->rate_limit_bps);
            if (r->tokens_bytes > r->rate_limit_bps * 2)
                r->tokens_bytes = r->rate_limit_bps * 2; /* burst cap = 2x rate */
        }
        if (r->rate_limit_pps > 0) {
            r->tokens_pkts += (uint64_t)(elapsed * r->rate_limit_pps);
            if (r->tokens_pkts > r->rate_limit_pps * 2)
                r->tokens_pkts = r->rate_limit_pps * 2;
        }
        r->last_refill = now;
    }

    /* Check tokens */
    if (r->rate_limit_bps > 0 && r->tokens_bytes < (uint64_t)pkt_bytes) {
        r->drop_count++;
        return 0;
    }
    if (r->rate_limit_pps > 0 && r->tokens_pkts < 1) {
        r->drop_count++;
        return 0;
    }

    /* Consume tokens */
    if (r->rate_limit_bps > 0) r->tokens_bytes -= pkt_bytes;
    if (r->rate_limit_pps > 0) r->tokens_pkts--;
    return 1;
}

static void forward_packet(rule_t *r, const u_char *pkt, int len) {
    /* Rate limiting */
    if (!rate_limit_check(r, len)) return;

    u_char buf[SNAP_LEN + 4]; /* +4 for possible VLAN tag insertion */
    const u_char *out_pkt = pkt;
    int out_len = len;

    /* VLAN manipulation */
    switch (r->vlan_action) {
    case VLAN_ADD:
        out_len = vlan_tag_add(pkt, len, r->vlan_new_id, buf, sizeof(buf));
        out_pkt = buf;
        break;
    case VLAN_REMOVE:
        out_len = vlan_tag_remove(pkt, len, buf, sizeof(buf));
        out_pkt = buf;
        break;
    case VLAN_CHANGE:
        out_len = vlan_tag_change(pkt, len, r->vlan_new_id, buf, sizeof(buf));
        out_pkt = buf;
        break;
    default:
        break;
    }

    /* Truncation */
    if (r->truncate > 0 && out_len > r->truncate) {
        out_len = r->truncate;
    }

    /* Send */
    pcap_t *h = get_output_handle(r->iface_out);
    if (h) {
        pthread_mutex_lock(&inject_lock);
        int rc = pcap_inject(h, out_pkt, out_len);
        pthread_mutex_unlock(&inject_lock);
        if (rc < 0) {
            log_msg("inject error on %s: %s", r->iface_out, pcap_geterr(h));
        }
    }
}

/* ── Per-interface capture thread ──────────────────────────────────────── */

typedef struct {
    char iface[FIELD_LEN];
    pcap_t *handle;
    uint64_t rx_bytes;            /* bytes delivered to packet_handler (one capture thread per ctx → no lock) */
    uint64_t recv, drop, ifdrop;  /* latest cumulative pcap_stats snapshot (written by the stats thread) */
} capture_ctx_t;

/* Published so the stats thread can sample pcap_stats per interface. ctxs lives
 * on main()'s stack for the whole process lifetime, so the pointer stays valid. */
static capture_ctx_t *g_ctxs = NULL;
static int            g_n_ctxs = 0;

static void packet_handler(u_char *user, const struct pcap_pkthdr *hdr,
                           const u_char *pkt) {
    capture_ctx_t *ctx = (capture_ctx_t *)user;
    int len = hdr->caplen;
    ctx->rx_bytes += (uint64_t)len; /* one capture thread per ctx → no lock needed */

    /* Reject runt frames — every downstream parser assumes >= 14 bytes. */
    if (len < ETH_HDR_MIN) return;

    /* Deduplication check (before rule matching) */
    if (is_duplicate(pkt, len)) return;

    /* L7 Protocol Detection (Application Intelligence) */
    int eth_hl = 14;
    uint16_t etype_be;
    memcpy(&etype_be, pkt + 12, 2);
    uint16_t etype = ntohs(etype_be);
    if (etype == ETHERTYPE_VLAN) {
        if (len < VLAN_HDR_MIN) return;
        eth_hl = 18;
        memcpy(&etype_be, pkt + 16, 2);
        etype = ntohs(etype_be);
    }
    const char *l7_proto = "unknown";
    if (etype == 0x0800 && len >= eth_hl + 20) {
        const struct ip *iph = (const struct ip *)(pkt + eth_hl);
        int ip_hl = iph->ip_hl * 4;
        /* ip_hl is an attacker-controlled nibble. Reject a header shorter
         * than the minimum or one that runs past the captured bytes before
         * deriving any L7 offset (mirrors the guard in match_rule). */
        if (ip_hl < 20 || eth_hl + ip_hl > len) goto l7_done;
        int sport = 0, dport = 0;
        const uint8_t *l7_payload = pkt + eth_hl + ip_hl;
        int l7_len = len - eth_hl - ip_hl;
        if (iph->ip_p == IPPROTO_TCP && len >= eth_hl + ip_hl + 20) {
            const struct tcphdr *tcp = (const struct tcphdr *)(pkt + eth_hl + ip_hl);
            sport = ntohs(tcp->th_sport); dport = ntohs(tcp->th_dport);
            int tcp_hl = tcp->th_off * 4;
            l7_payload = pkt + eth_hl + ip_hl + tcp_hl;
            l7_len = len - eth_hl - ip_hl - tcp_hl;
        } else if (iph->ip_p == IPPROTO_UDP && len >= eth_hl + ip_hl + 8) {
            const struct udphdr *udp = (const struct udphdr *)(pkt + eth_hl + ip_hl);
            sport = ntohs(udp->uh_sport); dport = ntohs(udp->uh_dport);
            l7_payload = pkt + eth_hl + ip_hl + 8;
            l7_len = len - eth_hl - ip_hl - 8;
        }
        if (l7_len > 0)
            l7_proto = detect_l7_protocol(l7_payload, l7_len, iph->ip_p, sport, dport);
    } else if (etype == 0x88CC) {
        l7_proto = "profinet"; /* PROFINET uses EtherType 0x8892, LLDP=0x88CC */
    }
l7_done:
    dpi_record(l7_proto, len);

    /* DPI-based routing (if any DPI rules configured). Snapshot the rule
     * table under dpi_lock so a concurrent load_dpi_config() cannot present
     * a half-written (non-NUL-terminated) entry to the strcmp below. */
    dpi_rule_t dpi_snap[DPI_STATS_SIZE];
    int dpi_snap_n;
    pthread_mutex_lock(&dpi_lock);
    dpi_snap_n = dpi_rule_count;
    if (dpi_snap_n > 0) memcpy(dpi_snap, dpi_rules, sizeof(dpi_rule_t) * (size_t)dpi_snap_n);
    pthread_mutex_unlock(&dpi_lock);

    if (dpi_snap_n > 0 && strcmp(l7_proto, "unknown") != 0) {
        for (int d = 0; d < dpi_snap_n; d++) {
            if (strcmp(dpi_snap[d].proto, l7_proto) != 0) continue;
            if (strcmp(dpi_snap[d].action, "drop") == 0) return; /* drop packet */
            if (strcmp(dpi_snap[d].action, "forward") == 0 || strcmp(dpi_snap[d].action, "mirror") == 0) {
                pcap_t *h = get_output_handle(dpi_snap[d].output);
                if (h) {
                    pthread_mutex_lock(&inject_lock);
                    pcap_inject(h, pkt, len);
                    pthread_mutex_unlock(&inject_lock);
                }
                if (strcmp(dpi_snap[d].action, "forward") == 0)
                    return; /* DPI forwarded, skip normal rules */
            }
        }
    }

    pthread_mutex_lock(&rules_lock);
    for (int i = 0; i < rule_count; i++) {
        rule_t *r = &rules[i];
        if (strcmp(r->iface_in, ctx->iface) != 0) continue;

        int matched = match_rule(r, pkt, len);
        if (r->exclude) matched = !matched;

        if (matched) {
            r->match_count++;
            r->byte_count += len;
            forward_packet(r, pkt, len);
        }
    }
    pthread_mutex_unlock(&rules_lock);
}

static void *capture_thread(void *arg) {
    capture_ctx_t *ctx = (capture_ctx_t *)arg;
    log_msg("Capture thread started for %s", ctx->iface);

    while (running) {
        int ret = pcap_dispatch(ctx->handle, 64, packet_handler, (u_char *)ctx);
        if (ret < 0 && running) {
            log_msg("pcap_dispatch error on %s: %s", ctx->iface, pcap_geterr(ctx->handle));
            break;
        }
    }

    log_msg("Capture thread stopped for %s", ctx->iface);
    return NULL;
}

/* ── Stats printer thread ──────────────────────────────────────────────── */

/* Atomic write (tmp+rename) of the dpstats-compatible per-iface counters, so a
 * load-test harness (or the Go side) can read capture recv/drop programmatically.
 * Mirrors the AF_XDP variant's schema (mode "libpcap"). */
static void write_stats_json(void) {
    char tmp[256];
    snprintf(tmp, sizeof tmp, "%s.tmp", STATS_JSON);
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    fprintf(f, "{\"mode\":\"libpcap\",\"ts\":%ld,\"ifaces\":{", (long)time(NULL));
    for (int i = 0; i < g_n_ctxs; i++) {
        capture_ctx_t *c = &g_ctxs[i];
        fprintf(f,
                "%s\"%s\":{\"rx_pkts\":%llu,\"rx_bytes\":%llu,"
                "\"tx_pkts\":0,\"tx_bytes\":0,"
                "\"rx_drop\":%llu,\"tx_drop\":0}",
                i == 0 ? "" : ",", c->iface,
                (unsigned long long)c->recv,
                (unsigned long long)c->rx_bytes,
                (unsigned long long)(c->drop + c->ifdrop));
    }
    fputs("}}", f);
    fclose(f);
    rename(tmp, STATS_JSON);
}

static void *stats_thread(void *arg) {
    (void)arg;
    while (running) {
        sleep(STATS_INTERVAL);
        if (!running) break;

        /* Capture-layer health: pcap_stats exposes the kernel ring-buffer drops
         * (ps_drop) — the signal that the broker is falling behind the wire, which
         * NIC /proc counters don't show. Only this thread reads pcap_stats, so the
         * cumulative counters libpcap maintains stay consistent. */
        for (int i = 0; i < g_n_ctxs; i++) {
            struct pcap_stat ps;
            if (g_ctxs[i].handle && pcap_stats(g_ctxs[i].handle, &ps) == 0) {
                g_ctxs[i].recv = ps.ps_recv;
                g_ctxs[i].drop = ps.ps_drop;
                g_ctxs[i].ifdrop = ps.ps_ifdrop;
                unsigned long long tot = (unsigned long long)ps.ps_recv + ps.ps_drop;
                double pct = tot ? (100.0 * (double)(ps.ps_drop + ps.ps_ifdrop) / (double)tot) : 0.0;
                log_msg("Capture %s: recv=%u drop=%u ifdrop=%u (%.2f%% dropped)",
                        g_ctxs[i].iface, ps.ps_recv, ps.ps_drop, ps.ps_ifdrop, pct);
            }
        }
        write_stats_json();

        pthread_mutex_lock(&rules_lock);
        for (int i = 0; i < rule_count; i++) {
            if (rules[i].match_count > 0) {
                log_msg("Rule %d [%s→%s]: %lu pkts, %lu bytes",
                        i, rules[i].iface_in, rules[i].iface_out,
                        rules[i].match_count, rules[i].byte_count);
            }
        }
        pthread_mutex_unlock(&rules_lock);

        check_for_updates();
    }
    return NULL;
}

/* ── Main ──────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;

    /* Open log */
    log_fp = fopen(LOG_FILE, "a");
    if (!log_fp) { perror("log"); return 1; }

    /* Write status & PID */
    write_file(STATUS_FILE, "running");
    char pidbuf[16];
    snprintf(pidbuf, sizeof(pidbuf), "%d", getpid());
    write_file(PID_FILE, pidbuf);

    /* Signal handling */
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    log_msg("Packet Broker starting (PID %d)", getpid());

    /* Load configs */
    load_rules();
    load_dedup_config();
    load_dpi_config();
    if (rule_count == 0) {
        log_msg("No rules loaded, waiting for rules.conf...");
        while (running && rule_count == 0) {
            sleep(2);
            check_for_updates();
        }
    }

    /* Collect unique input interfaces */
    char unique_ifaces[MAX_INTERFACES][FIELD_LEN];
    int n_ifaces = 0;
    pthread_mutex_lock(&rules_lock);
    for (int i = 0; i < rule_count; i++) {
        int found = 0;
        for (int j = 0; j < n_ifaces; j++) {
            if (strcmp(unique_ifaces[j], rules[i].iface_in) == 0) { found = 1; break; }
        }
        if (!found && n_ifaces < MAX_INTERFACES) {
            strncpy(unique_ifaces[n_ifaces], rules[i].iface_in, FIELD_LEN-1);
            n_ifaces++;
        }
    }
    pthread_mutex_unlock(&rules_lock);

    /* Open capture handles and start threads */
    pthread_t threads[MAX_INTERFACES];
    capture_ctx_t ctxs[MAX_INTERFACES];
    int n_threads = 0;

    for (int i = 0; i < n_ifaces; i++) {
        char errbuf[PCAP_ERRBUF_SIZE];
        /* The control plane brings interfaces UP immediately before exec'ing
         * the broker; a mirror NIC can transiently report "capture not
         * supported" while the link settles, leaving the broker running with
         * zero capture threads. Retry a few times so a startup race doesn't
         * silently disable capture. */
        pcap_t *h = NULL;
        for (int attempt = 1; attempt <= 5; attempt++) {
            h = pcap_open_live(unique_ifaces[i], SNAP_LEN, 1, 100, errbuf);
            if (h) break;
            log_msg("Cannot open %s (attempt %d/5): %s", unique_ifaces[i], attempt, errbuf);
            if (attempt < 5) sleep(1);
        }
        if (!h) {
            log_msg("Giving up on %s after 5 attempts", unique_ifaces[i]);
            continue;
        }
        strncpy(ctxs[n_threads].iface, unique_ifaces[i], FIELD_LEN-1);
        ctxs[n_threads].handle = h;
        pthread_create(&threads[n_threads], NULL, capture_thread, &ctxs[n_threads]);
        n_threads++;
        log_msg("Listening on %s", unique_ifaces[i]);
    }

    /* Publish the capture contexts so the stats thread can sample pcap_stats. */
    g_ctxs = ctxs;
    g_n_ctxs = n_threads;

    /* Stats thread */
    pthread_t stats_tid;
    pthread_create(&stats_tid, NULL, stats_thread, NULL);

    log_msg("Broker running with %d interfaces, %d rules", n_threads, rule_count);

    /* Wait for signal */
    while (running) {
        sleep(1);
    }

    /* Cleanup */
    log_msg("Shutting down...");
    for (int i = 0; i < n_threads; i++) {
        pcap_breakloop(ctxs[i].handle);
    }
    for (int i = 0; i < n_threads; i++) {
        pthread_join(threads[i], NULL);
        pcap_close(ctxs[i].handle);
    }
    pthread_join(stats_tid, NULL);

    /* Close output handles */
    for (int i = 0; i < out_cache_count; i++) {
        pcap_close(out_cache[i].handle);
    }

    write_file(STATUS_FILE, "stopped");
    log_msg("Broker stopped");
    fclose(log_fp);
    return 0;
}
