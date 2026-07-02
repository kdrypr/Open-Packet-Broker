# Open Packet Broker — build targets.
#
#   make          build the Go control plane / web UI  (pure Go, no CGO)
#   make c        build the C data plane (libpcap)      (Linux, needs libpcap-dev)
#   make afxdp    build the AF_XDP zero-copy data plane (needs clang+libbpf+libxdp)
#   make clean    remove built binaries

GO ?= go
CC ?= gcc

.PHONY: all c afxdp clean

all:
	$(GO) build ./cmd/packet-broker

c:
	$(CC) -O2 -o packet_broker c_src/packet_broker_libpcap.c -lpcap -lpthread

afxdp:
	clang -O2 -o packet_broker_afxdp c_src/packet_broker_afxdp.c c_src/bpf_helpers.c -lpcap -lbpf -lxdp

clean:
	rm -f packet-broker packet_broker packet_broker_afxdp
