/*
 * fuzz_parse.c — libFuzzer harness for the packet-parsing core.
 *
 * This is the highest-risk code in the product: header parsers that act on
 * untrusted, attacker-controlled network bytes at line rate. We #include the
 * production libpcap translation unit (with its main() renamed) so the fuzzer
 * can reach its static parse functions directly, then drive each with
 * arbitrary input under AddressSanitizer + UndefinedBehaviorSanitizer.
 *
 * Build (on a Linux box with clang + libpcap-dev):
 *   clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *         -o fuzz_parse fuzz_parse.c -lpcap -lpthread
 * Run:
 *   ./fuzz_parse -max_len=70000 -rss_limit_mb=4096 corpus/
 *
 * A crash/leak/UB writes a `crash-*` reproducer; feed it back to debug.
 */

#define main pb_unused_main
#include "packet_broker_libpcap.c"
#undef main

#include <stdint.h>
#include <string.h>

/* Build a rule that exercises as many inspection branches as possible:
 * string match (memmem), IP+CIDR, MAC, VLAN, ports, TCP flags. `seed` lets
 * the fuzzer flip a few rule knobs from the input so both match and
 * no-match / exclude paths are covered. */
static void make_rule(rule_t *r, uint8_t seed) {
    memset(r, 0, sizeof *r);
    strncpy(r->iface_in,  "in",  FIELD_LEN - 1);
    strncpy(r->iface_out, "out", FIELD_LEN - 1);
    strncpy(r->protocol,  "TCP", FIELD_LEN - 1);
    strncpy(r->tcp_flags, "S",   FIELD_LEN - 1);
    strncpy(r->string_match, "GET", FIELD_LEN - 1);
    r->dest_port = 80;
    r->src_port  = 0;
    r->src_ip    = 0x0A000001; r->src_mask = 0xFFFFFF00; /* 10.0.0.1/24 */
    r->dst_ip    = 0xC0A80101; r->dst_mask = 0xFFFFFFFF; /* 192.168.1.1/32 */
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
    const u_char *pkt = (const u_char *)data;

    uint8_t s0 = data[0];
    int sp = size >= 2 ? data[0] : 0;
    int dp = size >= 2 ? data[1] : 0;

    /* L7 classifier (also reached internally via offsets in real traffic). */
    detect_l7_protocol(pkt, len, IPPROTO_TCP, sp, dp);
    detect_l7_protocol(pkt, len, IPPROTO_UDP, sp, dp);
    detect_l7_protocol(pkt, len, IPPROTO_ICMP, sp, dp);

    /* VLAN tag manipulation into a correctly-sized output buffer. */
    static u_char out[SNAP_LEN + 4];
    vlan_tag_add(pkt, len, 0x123, out, sizeof out);
    vlan_tag_remove(pkt, len, out, sizeof out);
    vlan_tag_change(pkt, len, 0x456, out, sizeof out);
    /* Also hit the tight-buffer rejection paths. */
    vlan_tag_add(pkt, len, 0x123, out, len);
    has_vlan_tag(pkt, len);
    get_vlan_id(pkt, len);

    /* Dedup CRC over first N bytes. */
    is_duplicate(pkt, len);

    /* Rule matching across two knob sets. */
    rule_t r;
    make_rule(&r, s0);
    match_rule(&r, pkt, len);
    make_rule(&r, (uint8_t)(s0 ^ 0xFF));
    match_rule(&r, pkt, len);

    return 0;
}
