package safedial

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// publicDNS are the fallback resolvers used when the host's own resolver (e.g. a
// flaky systemd-resolved stub with an unreliable upstream) fails or times out on a
// name. The system resolver is tried FIRST, so split-horizon / private DNS for
// internal FQDNs keeps working; only names the system path can't answer fall back
// to public DNS. Appliances commonly hit this: an internal SIEM resolves fine while
// a public cloud API (CrowdStrike, Defender) intermittently times out.
var publicDNS = []string{"8.8.8.8:53", "1.1.1.1:53"}

// resolveResilient resolves host via the system resolver first, then public DNS.
func resolveResilient(ctx context.Context, host string) []net.IP {
	sys := &net.Resolver{PreferGo: true}
	c1, cancel1 := context.WithTimeout(ctx, 3*time.Second)
	addrs, err := sys.LookupIPAddr(c1, host)
	cancel1()
	if err == nil && len(addrs) > 0 {
		return ipsOf(addrs)
	}
	for _, srv := range publicDNS {
		r := &net.Resolver{PreferGo: true, Dial: func(c context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(c, network, srv)
		}}
		c2, cancel2 := context.WithTimeout(ctx, 4*time.Second)
		a, e := r.LookupIPAddr(c2, host)
		cancel2()
		if e == nil && len(a) > 0 {
			return ipsOf(a)
		}
	}
	return nil
}

func ipsOf(as []net.IPAddr) []net.IP {
	out := make([]net.IP, 0, len(as))
	for _, a := range as {
		out = append(out, a.IP)
	}
	return out
}

// resilientDialContext resolves with a public-DNS fallback, rejects SSRF-blocked
// peers (per resolved IP, defeating DNS rebinding), and dials the first allowed IP.
// TLS is still layered by the Transport using the original hostname, so SNI and
// certificate verification are unaffected by dialing the resolved IP directly.
func resilientDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	if ip := net.ParseIP(host); ip != nil {
		if blockedForConnector(ip) {
			return nil, fmt.Errorf("blocked address: %s", host)
		}
		return d.DialContext(ctx, network, address)
	}
	ips := resolveResilient(ctx, host)
	if len(ips) == 0 {
		return nil, fmt.Errorf("lookup %s: no addresses (system + public DNS failed)", host)
	}
	var lastErr error
	for _, ip := range ips {
		if blockedForConnector(ip) {
			lastErr = fmt.Errorf("blocked address: %s", ip)
			continue
		}
		c, e := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if e == nil {
			return c, nil
		}
		lastErr = e
	}
	return nil, lastErr
}

// blockedForConnector is BlockedIP (metadata / link-local / unspecified) plus a
// loopback block: an outbound EDR/SIEM/SOAR/firewall connector reaching the
// appliance's OWN loopback services are never
// legitimate and would be an operator-reachable SSRF read primitive. RFC1918 stays
// allowed so on-prem SIEMs/firewalls on the management LAN still work.
func blockedForConnector(ip net.IP) bool {
	return ip == nil || ip.IsLoopback() || BlockedIP(ip)
}

// GuardResilient is like Guard but resolves names with a public-DNS fallback for
// outbound integration clients (EDR / SIEM / SOAR / firewall) that reach a mix of
// internal FQDNs and public cloud APIs from a host with a flaky resolver.
// Connectors additionally refuse loopback (see blockedForConnector).
func GuardResilient(tr *http.Transport) *http.Transport {
	tr.DialContext = resilientDialContext
	return tr
}
