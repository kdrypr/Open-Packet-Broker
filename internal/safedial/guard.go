package safedial

import (
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

// BlockedIP reports whether dialing ip should be refused for an integration
// console connection. It blocks ALL known cloud metadata endpoints (the SSRF
// prize — AWS/GCP/Azure 169.254.169.254, Alibaba 100.100.100.200, AWS IMDS IPv6
// fd00:ec2::/64), link-local and the unspecified address, but ALLOWS loopback +
// RFC1918 because firewall/EDR/SOAR management planes legitimately live on
// internal networks.
func BlockedIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	for _, n := range metadataBlocks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// guardControl enforces BlockedIP on the resolved peer (re-checked per dial, so
// DNS rebinding can't slip past).
func guardControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if BlockedIP(net.ParseIP(host)) {
		return fmt.Errorf("blocked address: %s", host)
	}
	return nil
}

// Guard installs the relaxed dial guard on tr and returns it (callers keep their
// own TLS config). Use for outbound integration consoles that may be on RFC1918.
func Guard(tr *http.Transport) *http.Transport {
	tr.DialContext = (&net.Dialer{Timeout: 10 * time.Second, Control: guardControl}).DialContext
	return tr
}
