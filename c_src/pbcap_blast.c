/* pbcap_blast — raw AF_PACKET load generator for the broker capacity test.
 *
 * Sends a fixed, valid Ethernet/IPv4/UDP frame on <iface> for <secs> seconds, as
 * fast as the kernel accepts or capped at <pps>, then prints one JSON line:
 *   {"sent":N,"secs":S,"pps":P,"size":B}
 *
 * Paired with pbcap_loadtest.py, which compares "sent" against the broker's
 * pcap_stats (recv/drop) to find the pps at which the capture path starts losing
 * packets. Build:  gcc -O2 -o pbcap_blast pbcap_blast.c
 *
 * usage: pbcap_blast <iface> <pkt_size> <secs> [pps_cap]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <iface> <pkt_size> <secs> [pps_cap]\n", argv[0]);
        return 2;
    }
    const char *iface = argv[1];
    int size = atoi(argv[2]);
    if (size < 60) size = 60;
    if (size > 1514) size = 1514;
    double secs = atof(argv[3]);
    long pps_cap = argc > 4 ? atol(argv[4]) : 0;

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) { perror("socket"); return 1; }
    int sndbuf = 8 << 20;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof sndbuf);

    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) { perror("SIOCGIFINDEX"); return 1; }

    unsigned char dmac[6] = {0x02, 0, 0, 0, 0, 2};
    unsigned char smac[6] = {0x02, 0, 0, 0, 0, 1};
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof sll);
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_halen = 6;
    memcpy(sll.sll_addr, dmac, 6);

    /* Build one Ethernet/IPv4/UDP frame; checksums left zero (the broker parses
     * but does not validate them). */
    unsigned char buf[1514];
    memset(buf, 0, sizeof buf);
    memcpy(buf, dmac, 6);
    memcpy(buf + 6, smac, 6);
    buf[12] = 0x08; buf[13] = 0x00; /* EtherType IPv4 */
    int iplen = size - 14;
    buf[14] = 0x45;                 /* v4, IHL 5 */
    buf[16] = (iplen >> 8) & 0xff; buf[17] = iplen & 0xff;
    buf[22] = 64;                   /* TTL */
    buf[23] = 17;                   /* proto UDP */
    uint32_t sip = htonl(0x0a010101), dip = htonl(0x0a010102);
    memcpy(buf + 26, &sip, 4);
    memcpy(buf + 30, &dip, 4);
    uint16_t sport = htons(1234), dport = htons(9999), ulen = htons((uint16_t)(iplen - 20));
    memcpy(buf + 34, &sport, 2);
    memcpy(buf + 36, &dport, 2);
    memcpy(buf + 38, &ulen, 2);

    double t0 = now_s(), tend = t0 + secs;
    unsigned long long sent = 0;
    for (;;) {
        double t = now_s();
        if (t >= tend) break;
        if (pps_cap > 0) {
            double target = (t - t0) * (double)pps_cap;
            if ((double)sent >= target) { usleep(100); continue; }
        }
        ssize_t n = sendto(fd, buf, size, 0, (struct sockaddr *)&sll, sizeof sll);
        if (n > 0) sent++;
        else usleep(20); /* ENOBUFS under burst — brief pause, then retry */
    }
    double dur = now_s() - t0;
    printf("{\"sent\":%llu,\"secs\":%.3f,\"pps\":%.0f,\"size\":%d}\n",
           sent, dur, dur > 0 ? (double)sent / dur : 0.0, size);
    return 0;
}
