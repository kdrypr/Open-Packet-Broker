// Package safedial provides an outbound dialer that refuses to connect
// to loopback, RFC1918, link-local, multicast, unspecified, or cloud
// metadata addresses (169.254.169.254 etc).
//
// Used by every outbound HTTP client in the codebase: cluster
// heartbeats, alert webhooks, mail (Microsoft Graph). Closes the SSRF
// class — an attacker-controlled admin can no longer point cluster /
// webhook URLs at internal services.
//
// Defends against DNS rebinding: the resolved IP is checked at dial
// time (not just at config-save time), so a host whose DNS TTL flips
// to a private IP between validation and use is still rejected.
package safedial

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

// ErrPrivateIP is returned when the dialer is asked to connect to an
// IP that falls in a reserved/private range.
var ErrPrivateIP = errors.New("safedial: target IP is private/loopback/link-local/metadata")

// Cloud metadata IPs explicitly blocked even though they may be
// reachable from the appliance's network — fetching them is almost
// always an SSRF probe rather than legitimate.
var metadataBlocks = []*net.IPNet{
	mustCIDR("169.254.169.254/32"), // AWS / GCP / Azure
	mustCIDR("100.100.100.200/32"), // Alibaba Cloud
	mustCIDR("fd00:ec2::/64"),      // AWS IMDS v2 IPv6
}

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic("safedial: bad embedded CIDR " + s)
	}
	return n
}

// IsPrivate reports whether ip should be refused. It covers all
// reserved ranges that `net.IP.IsPrivate` doesn't (loopback, link-
// local, metadata) plus the obvious RFC1918 set IsPrivate already
// handles.
func IsPrivate(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	for _, n := range metadataBlocks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Dialer returns a net.Dialer whose Control func rejects private
// destinations. Use it as `http.Transport{DialContext: Dialer().DialContext}`.
//
// Resolution happens before Control fires (Go resolves then calls
// Control once per address it'll try), so we get to veto each
// candidate IP individually — defeats DNS rebinding.
func Dialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(_ string, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				host = address
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("safedial: unparsable host %q", host)
			}
			if IsPrivate(ip) {
				return fmt.Errorf("%w: %s", ErrPrivateIP, ip)
			}
			return nil
		},
	}
}

// IsForbiddenForRelay reports whether ip must never be used as an outbound
// relay target (SMTP, syslog) regardless of deployment posture: loopback,
// unspecified, multicast, and cloud-metadata addresses. Unlike IsPrivate it
// does NOT reject RFC1918 / link-local, because an internal mail or syslog
// relay is a legitimate configuration — but pointing the relay at the
// loopback interface or the cloud metadata service never is.
func IsForbiddenForRelay(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsUnspecified() ||
		ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	for _, n := range metadataBlocks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// RelayDialer returns a net.Dialer that vetoes only the relay-forbidden set
// (see IsForbiddenForRelay) at connect time — defeating DNS rebinding the
// same way Dialer does — while still allowing internal RFC1918 relays.
// Use for SMTP/syslog where an internal server is a normal configuration.
func RelayDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout,
		Control: func(_ string, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				host = address
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("safedial: unparsable host %q", host)
			}
			if IsForbiddenForRelay(ip) {
				return fmt.Errorf("%w: %s", ErrPrivateIP, ip)
			}
			return nil
		},
	}
}

// Client returns an *http.Client suitable for outbound calls to
// administrator-supplied URLs. Redirects are disabled (an open
// redirect on the target would otherwise bypass our IP check on the
// final hop).
func Client(timeout time.Duration) *http.Client {
	t := &http.Transport{
		DialContext:           Dialer().DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: t,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
