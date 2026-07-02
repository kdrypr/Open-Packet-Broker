package safedial

import (
	"net"
	"testing"
)

// Connector dialers must refuse the appliance's own loopback and cloud metadata
// (operator-reachable SSRF), while still allowing RFC1918 collectors on the LAN.
func TestBlockedForConnector(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},       // loopback — the new block
		{"::1", true},             // IPv6 loopback
		{"169.254.169.254", true}, // cloud metadata
		{"0.0.0.0", true},         // unspecified
		{"10.1.2.3", false},       // RFC1918 collector — allowed
		{"192.168.1.50", false},   // RFC1918 — allowed
		{"8.8.8.8", false},        // public — allowed
	}
	for _, tc := range tests {
		if got := blockedForConnector(net.ParseIP(tc.ip)); got != tc.want {
			t.Errorf("blockedForConnector(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
	if !blockedForConnector(nil) {
		t.Error("blockedForConnector(nil) must be true (fail closed)")
	}
}

func TestIsPrivate(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},       // loopback
		{"10.0.0.1", true},        // RFC1918
		{"192.168.1.1", true},     // RFC1918
		{"172.16.0.1", true},      // RFC1918
		{"169.254.169.254", true}, // AWS/GCP metadata
		{"169.254.1.1", true},     // link-local
		{"100.100.100.200", true}, // Alibaba metadata
		{"0.0.0.0", true},         // unspecified
		{"224.0.0.1", true},       // multicast
		{"::1", true},             // IPv6 loopback
		{"fe80::1", true},         // IPv6 link-local
		{"fd00:ec2::1", true},     // IPv6 IMDS

		{"8.8.8.8", false},       // public DNS
		{"1.1.1.1", false},       // public DNS
		{"93.184.216.34", false}, // example.com
	}
	for _, tc := range tests {
		ip := net.ParseIP(tc.ip)
		if got := IsPrivate(ip); got != tc.want {
			t.Errorf("IsPrivate(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestIsPrivate_NilSafe(t *testing.T) {
	if !IsPrivate(nil) {
		t.Error("nil IP should be treated as private/refused")
	}
}
