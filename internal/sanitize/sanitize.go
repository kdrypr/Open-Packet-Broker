// Package sanitize provides input validation and sanitization functions
// for the Packet Broker web application (OWASP Top 10 hardening).
package sanitize

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

var (
	// Safe patterns
	reInterface  = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]{1,32}$`)
	reMAC        = regexp.MustCompile(`^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$`)
	reBPFSafe    = regexp.MustCompile(`^[a-zA-Z0-9\s\.\:\(\)\/\-\_\!\&\|\>\<\=\[\]]+$`)
	rePort       = regexp.MustCompile(`^[0-9]{1,5}$`)
	reProtocol   = regexp.MustCompile(`^(?i)(tcp|udp|icmp|0)$`)
	reTCPFlags   = regexp.MustCompile(`^[SAFRUP0]+$`)
	reVLANAction = regexp.MustCompile(`^(none|add|remove|change)$`)
)

// Interface validates a network interface name.
func Interface(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("interface name required")
	}
	if !reInterface.MatchString(s) {
		return "", fmt.Errorf("invalid interface name: %q", s)
	}
	return s, nil
}

// Port validates a network port number (0-65535). "0" means any.
func Port(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return "0", nil
	}
	if !rePort.MatchString(s) {
		return "", fmt.Errorf("invalid port: %q", s)
	}
	n := 0
	fmt.Sscanf(s, "%d", &n)
	if n < 0 || n > 65535 {
		return "", fmt.Errorf("port out of range: %d", n)
	}
	return s, nil
}

// Protocol validates a protocol string.
func Protocol(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return "0", nil
	}
	if !reProtocol.MatchString(s) {
		return "", fmt.Errorf("invalid protocol: %q (use TCP, UDP, ICMP, or 0)", s)
	}
	return strings.ToUpper(s), nil
}

// TCPFlags validates TCP flag characters.
func TCPFlags(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return "0", nil
	}
	if !reTCPFlags.MatchString(s) {
		return "", fmt.Errorf("invalid TCP flags: %q (use S,A,F,R,P,U)", s)
	}
	return s, nil
}

// VLANID validates a VLAN ID (0-4094).
func VLANID(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return "0", nil
	}
	n := 0
	fmt.Sscanf(s, "%d", &n)
	if n < 0 || n > 4094 {
		return "", fmt.Errorf("VLAN ID out of range: %d (0-4094)", n)
	}
	return s, nil
}

// VLANAction validates a VLAN action string.
func VLANAction(s string) (string, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return "none", nil
	}
	if !reVLANAction.MatchString(s) {
		return "", fmt.Errorf("invalid VLAN action: %q", s)
	}
	return s, nil
}

// IP validates an IP address or CIDR notation. "0" means any.
func IP(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return "0", nil
	}
	// Try CIDR
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		if err != nil {
			return "", fmt.Errorf("invalid CIDR: %q", s)
		}
		return s, nil
	}
	// Try plain IP
	if net.ParseIP(s) == nil {
		return "", fmt.Errorf("invalid IP: %q", s)
	}
	return s, nil
}

// MAC validates a MAC address. "0" means any.
func MAC(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return "0", nil
	}
	if !reMAC.MatchString(s) {
		return "", fmt.Errorf("invalid MAC: %q (format: AA:BB:CC:DD:EE:FF)", s)
	}
	return s, nil
}

// BPFFilter validates a BPF filter expression.
// Only allows safe characters to prevent injection.
func BPFFilter(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if len(s) > 256 {
		return "", fmt.Errorf("BPF filter too long (max 256 chars)")
	}
	if !reBPFSafe.MatchString(s) {
		return "", fmt.Errorf("BPF filter contains invalid characters")
	}
	// Block obvious shell metacharacters
	for _, bad := range []string{";", "`", "$", "{", "}", "\\", "'", "\""} {
		if strings.Contains(s, bad) {
			return "", fmt.Errorf("BPF filter contains forbidden character: %s", bad)
		}
	}
	return s, nil
}

// WebhookURL validates a webhook URL and blocks SSRF attacks.
func WebhookURL(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %q", s)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("URL must use http or https")
	}
	host := u.Hostname()
	if err := blockPrivateHost(host); err != nil {
		return "", err
	}
	return s, nil
}

// ExternalHost validates a hostname/IP for external services (syslog, SMTP).
// Allows private IPs since syslog/SMTP servers are typically internal.
func ExternalHost(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("host required")
	}
	if len(s) > 253 {
		return "", fmt.Errorf("hostname too long")
	}
	// Block obvious injection
	for _, bad := range []string{";", "`", "$", "'", "\"", "\n", "\r", " "} {
		if strings.Contains(s, bad) {
			return "", fmt.Errorf("hostname contains invalid characters")
		}
	}
	return s, nil
}

// ConfField validates a single field destined for one of the positional,
// comma-separated config files consumed by the root C data plane
// (dpi.conf, masking.conf, …). It rejects commas (which corrupt field
// boundaries) and CR/LF (which would inject entirely new directive lines).
// Empty is allowed — callers decide whether a field is required.
func ConfField(s string) (string, error) {
	if strings.ContainsAny(s, ",\r\n") {
		return "", fmt.Errorf("value may not contain a comma or newline")
	}
	return s, nil
}

// ConfLine validates a free-form field (e.g. a regex pattern) that may
// legitimately contain commas but must never contain CR/LF — a newline
// would inject a new line into the C data plane's config file.
func ConfLine(s string) (string, error) {
	if strings.ContainsAny(s, "\r\n") {
		return "", fmt.Errorf("value may not contain a newline")
	}
	return s, nil
}

// OneOf returns s unchanged if it appears in allowed, else an error. Used to
// pin enum-like form fields (action, category, type) to a fixed allow-list
// before they reach a config file or the data plane.
func OneOf(s string, allowed ...string) (string, error) {
	for _, a := range allowed {
		if s == a {
			return s, nil
		}
	}
	return "", fmt.Errorf("invalid value %q (allowed: %s)", s, strings.Join(allowed, ", "))
}

// SanitizeCSVField removes characters that could break CSV parsing or inject data.
func CSVField(s string) string {
	s = strings.ReplaceAll(s, ",", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\"", "")
	// Prevent formula injection in spreadsheet tools
	for _, prefix := range []string{"=", "+", "-", "@", "\t"} {
		if strings.HasPrefix(s, prefix) {
			s = "'" + s
		}
	}
	return s
}

// Email validates an email address format.
func Email(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	// Basic RFC 5322 check
	if !strings.Contains(s, "@") || strings.Count(s, "@") != 1 {
		return "", fmt.Errorf("invalid email: %q", s)
	}
	parts := strings.SplitN(s, "@", 2)
	if len(parts[0]) == 0 || len(parts[1]) < 3 {
		return "", fmt.Errorf("invalid email: %q", s)
	}
	if len(s) > 254 {
		return "", fmt.Errorf("email too long")
	}
	return s, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func blockPrivateHost(host string) error {
	if host == "" {
		return fmt.Errorf("empty host")
	}
	lower := strings.ToLower(host)
	if lower == "localhost" || lower == "ip6-localhost" {
		return fmt.Errorf("localhost not allowed in webhook URL")
	}

	ip := net.ParseIP(host)
	if ip == nil {
		// Hostname — resolve to check for private IPs
		addrs, err := net.LookupIP(host)
		if err != nil {
			return nil // DNS lookup failed, allow (might be valid external host)
		}
		for _, addr := range addrs {
			if isPrivateIP(addr) {
				return fmt.Errorf("webhook URL resolves to private IP (%s)", addr)
			}
		}
		return nil
	}

	if isPrivateIP(ip) {
		return fmt.Errorf("private/internal IP not allowed in webhook URL (%s)", ip)
	}
	return nil
}

func isPrivateIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}
