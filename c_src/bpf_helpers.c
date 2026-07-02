/*
 * bpf_helpers.c — libpcap cBPF wrapper. Compiled standalone; the rest of
 * the AF_XDP binary does NOT include pcap/bpf.h to avoid `struct bpf_insn`
 * collisions with linux/bpf.h (pulled in via xdp/xsk.h → bpf/libbpf.h).
 */
#include "bpf_helpers.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pcap/pcap.h>

void *pb_bpf_compile(const char *expr, char *errbuf, int errbuf_size) {
    if (!expr || !*expr) return NULL;
    struct bpf_program *p = calloc(1, sizeof *p);
    if (!p) return NULL;
    /* DLT_EN10MB = Ethernet; snaplen 65535; optimize=1; mask=any */
    if (pcap_compile_nopcap(65535, DLT_EN10MB, p, expr, 1, 0xffffffff) != 0) {
        if (errbuf && errbuf_size > 0) {
            snprintf(errbuf, errbuf_size, "pcap_compile_nopcap failed for '%s'", expr);
        }
        free(p);
        return NULL;
    }
    return p;
}

int pb_bpf_match(const void *handle, const uint8_t *pkt, int len) {
    if (!handle) return 1;     /* no filter = pass */
    const struct bpf_program *p = (const struct bpf_program *)handle;
    if (!p->bf_insns) return 1;
    return bpf_filter(p->bf_insns, pkt, (unsigned)len, (unsigned)len) != 0;
}

void pb_bpf_free(void *handle) {
    if (!handle) return;
    struct bpf_program *p = (struct bpf_program *)handle;
    pcap_freecode(p);
    free(p);
}
