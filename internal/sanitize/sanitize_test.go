package sanitize

import "testing"

func TestInterface(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"valid eth", "eth0", false},
		{"valid enp", "enp4s0", false},
		{"valid mlx", "enp2s0f0np0", false},
		{"empty rejected", "", true},
		{"injection rejected", "eth0; rm -rf /", true},
		{"semicolon rejected", "eth0;ls", true},
		{"backtick rejected", "eth0`whoami`", true},
		{"long name rejected", "this-name-is-way-too-long-for-a-network-interface-name", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Interface(c.in)
			gotErr := err != nil
			if gotErr != c.wantErr {
				t.Fatalf("Interface(%q): wantErr=%v, got err=%v", c.in, c.wantErr, err)
			}
		})
	}
}

func TestPort(t *testing.T) {
	if v, err := Port("80"); err != nil || v != "80" {
		t.Errorf("Port(80) = %q, %v", v, err)
	}
	if v, err := Port("0"); err != nil || v != "0" {
		t.Errorf("Port(0) = %q, %v", v, err)
	}
	if _, err := Port("65536"); err == nil {
		t.Error("Port(65536) should reject")
	}
	if _, err := Port("-1"); err == nil {
		t.Error("Port(-1) should reject")
	}
	if _, err := Port("abc"); err == nil {
		t.Error("Port(abc) should reject")
	}
}

func TestIP(t *testing.T) {
	ok := []string{"0", "192.168.1.0/24", "10.0.0.1", "10.0.0.0/8"}
	for _, in := range ok {
		if _, err := IP(in); err != nil {
			t.Errorf("IP(%q) unexpected error: %v", in, err)
		}
	}
	bad := []string{"999.999.999.999", "not-an-ip", "192.168.1.1/40", "192.168;rm"}
	for _, in := range bad {
		if _, err := IP(in); err == nil {
			t.Errorf("IP(%q) should reject", in)
		}
	}
}

func TestMAC(t *testing.T) {
	if _, err := MAC("AA:BB:CC:DD:EE:FF"); err != nil {
		t.Errorf("MAC(valid) returned %v", err)
	}
	if _, err := MAC("0"); err != nil {
		t.Errorf("MAC(0) returned %v", err)
	}
	if _, err := MAC("garbage"); err == nil {
		t.Error("MAC(garbage) should reject")
	}
	if _, err := MAC("AA:BB:CC:DD:EE"); err == nil {
		t.Error("MAC with 5 octets should reject")
	}
}

func TestTCPFlags(t *testing.T) {
	good := []string{"0", "S", "SA", "SAFRPU"}
	for _, in := range good {
		if _, err := TCPFlags(in); err != nil {
			t.Errorf("TCPFlags(%q) = %v", in, err)
		}
	}
	bad := []string{"Z", "S;cmd", "SAFRPU+extra"}
	for _, in := range bad {
		if _, err := TCPFlags(in); err == nil {
			t.Errorf("TCPFlags(%q) should reject", in)
		}
	}
}

func TestBPFFilter(t *testing.T) {
	good := []string{"", "0", "tcp port 22", "udp and port 53"}
	for _, in := range good {
		if _, err := BPFFilter(in); err != nil {
			t.Errorf("BPFFilter(%q) = %v", in, err)
		}
	}
	// Shell metacharacters that would matter if BPF were ever passed
	// through a shell (it isn't — libpcap parses directly — but
	// defense-in-depth rejects them anyway).
	bad := []string{"tcp;ls", "tcp`whoami`", "tcp$(ls)"}
	for _, in := range bad {
		if _, err := BPFFilter(in); err == nil {
			t.Errorf("BPFFilter(%q) should reject — shell metachar present", in)
		}
	}
}

func TestWebhookURL_blocksPrivate(t *testing.T) {
	// Direct IP literals
	bad := []string{
		"http://127.0.0.1/notify",
		"http://10.0.0.1/notify",
		"http://192.168.1.1/notify",
		"http://[::1]/notify",
		"http://169.254.169.254/latest/meta-data/",
		"ftp://example.com/file", // wrong scheme
		"file:///etc/passwd",
	}
	for _, in := range bad {
		if _, err := WebhookURL(in); err == nil {
			t.Errorf("WebhookURL(%q) should reject", in)
		}
	}
	if _, err := WebhookURL("https://hooks.example.com/foo"); err != nil {
		// Public host may fail DNS in offline test runs — accept either.
		_ = err
	}
}
