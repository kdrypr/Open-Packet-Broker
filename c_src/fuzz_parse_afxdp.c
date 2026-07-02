/*
 * fuzz_parse_afxdp.c — libFuzzer harness for the AF_XDP data-plane parsers.
 *
 * AF_XDP is now the DEFAULT broker mode (packet_broker_afxdp.c), so its header
 * parsers — which are SEPARATELY WRITTEN from the libpcap variant, not byte-identical
 * — run on attacker-controlled wire bytes at line rate on the production path. The
 * libpcap fuzzer (fuzz_parse.c) does NOT cover them. This harness #includes the AF_XDP
 * translation unit (main() renamed) and drives its static parse functions directly so
 * the afxdp variant can't drift unfuzzed.
 *
 * Build (Linux box with clang + libxdp-dev + libbpf-dev + libelf-dev + libpcap-dev):
 *   clang -g -O1 -fsanitize=fuzzer,address,undefined -o fuzz_parse_afxdp \
 *         fuzz_parse_afxdp.c bpf_helpers.c \
 *         $(pkg-config --cflags --libs libxdp libbpf libelf) -lpcap -lpthread
 * Run:
 *   ./fuzz_parse_afxdp -max_len=70000 -rss_limit_mb=4096 corpus/
 */

#define main pb_unused_main
#include "packet_broker_afxdp.c"
#undef main

#include <stdint.h>
#include <string.h>

/* Mirror of fuzz_parse.c make_rule for the afxdp rule_t (same field layout). */
static void make_rule_afxdp(rule_t *r, uint8_t seed) {
    memset(r, 0, sizeof *r);
    strncpy(r->iface_in,  "in",  FIELD_LEN - 1);
    strncpy(r->iface_out, "out", FIELD_LEN - 1);
    strncpy(r->protocol,  "TCP", FIELD_LEN - 1);
    strncpy(r->tcp_flags, "S",   FIELD_LEN - 1);
    strncpy(r->string_match, "GET", FIELD_LEN - 1);
    r->dest_port = 80;
    r->src_ip    = 0x0A000001; r->src_mask = 0xFFFFFF00;
    r->dst_ip    = 0xC0A80101; r->dst_mask = 0xFFFFFFFF;
    memset(r->src_mac, 0xAA, 6); r->has_src_mac = 1;
    memset(r->dst_mac, 0xBB, 6); r->has_dst_mac = 1;
    r->vlan_id   = (seed & 1) ? 100 : 0;
    r->exclude   = (seed & 2) ? 1 : 0;
    r->vlan_action = (seed & 4) ? 1 : 0;
    r->vlan_new_id = 200;
    r->truncate  = (seed & 8) ? 64 : 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > 70000) return 0;
    int len = (int)size;
    const uint8_t *pkt = data;

    uint8_t s0 = data[0];
    int sp = size >= 2 ? data[0] : 0;
    int dp = size >= 2 ? data[1] : 0;

    detect_l7_protocol(pkt, len, IPPROTO_TCP, sp, dp);
    detect_l7_protocol(pkt, len, IPPROTO_UDP, sp, dp);
    detect_l7_protocol(pkt, len, IPPROTO_ICMP, sp, dp);

    static uint8_t out[FRAME_SIZE + 4];
    vlan_tag_add(pkt, len, 0x123, out, sizeof out);
    vlan_tag_remove(pkt, len, out, sizeof out);
    vlan_tag_change(pkt, len, 0x456, out, sizeof out);
    /* tight-buffer rejection path */
    vlan_tag_add(pkt, len, 0x123, out, len);
    has_vlan_tag(pkt, len);
    get_vlan_id(pkt, len);

    is_duplicate(pkt, len);

    rule_t r;
    make_rule_afxdp(&r, s0);
    match_rule(&r, pkt, len);
    make_rule_afxdp(&r, (uint8_t)(s0 ^ 0xFF));
    match_rule(&r, pkt, len);

    return 0;
}
