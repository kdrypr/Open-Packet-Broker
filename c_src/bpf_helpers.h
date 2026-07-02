/*
 * bpf_helpers.h — opaque cBPF compile/match interface.
 *
 * Wraps libpcap's pcap_compile_nopcap + bpf_filter so the caller does NOT
 * pull in pcap/bpf.h (which defines struct bpf_insn the same as
 * linux/bpf.h does in eBPF terms — and including both in one TU fails).
 *
 * Owner frees the returned handle via pb_bpf_free().
 */
#ifndef PB_BPF_HELPERS_H
#define PB_BPF_HELPERS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Compile a libpcap filter expression for DLT_EN10MB (ethernet).
 * Returns NULL on failure (and writes a short reason to errbuf if provided). */
void *pb_bpf_compile(const char *expr, char *errbuf, int errbuf_size);

/* Run filter on a single packet. Returns 1 on match, 0 on no match. */
int   pb_bpf_match(const void *handle, const uint8_t *pkt, int len);

/* Free the program returned by pb_bpf_compile. Safe on NULL. */
void  pb_bpf_free(void *handle);

#ifdef __cplusplus
}
#endif
#endif
