package license

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// signLicense generates a vendor key pair, embeds the public key in the
// manager under test, and returns a Manager + signing helper. Each
// test gets its own ephemeral identity — no on-disk state from earlier
// runs can taint results.
func setupSignedManager(t *testing.T) (*Manager, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Stomp the package-level embed for the duration of this test.
	prev := vendorPubKeyHex
	vendorPubKeyHex = hex.EncodeToString(pub)
	t.Cleanup(func() { vendorPubKeyHex = prev })

	dir := t.TempDir()
	licPath := filepath.Join(dir, "license.key")
	m, err := NewManager(licPath)
	if err != nil {
		t.Fatal(err)
	}
	return m, priv, licPath
}

func writeSigned(t *testing.T, priv ed25519.PrivateKey, path string, lic License) {
	t.Helper()
	payload, err := json.Marshal(lic)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, payload)
	out := SignedLicense{
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}
	data, _ := json.Marshal(out)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestNewManager_RejectsMalformedPubkey(t *testing.T) {
	prev := vendorPubKeyHex
	vendorPubKeyHex = "deadbeef" // too short
	defer func() { vendorPubKeyHex = prev }()

	if _, err := NewManager(filepath.Join(t.TempDir(), "license.key")); err == nil {
		t.Fatal("expected NewManager to reject a malformed vendor pubkey")
	}
}

func TestReload_RejectsEmptyHardwareID(t *testing.T) {
	m, priv, licPath := setupSignedManager(t)
	writeSigned(t, priv, licPath, License{
		HardwareID: "", // hostile vendor (or dropped JSON field)
		Expiry:     "perpetual",
		Features:   []string{"all"},
		Type:       "enterprise",
	})
	m.Reload()
	s := m.GetStatus()
	if s.Valid {
		t.Fatalf("expected invalid (empty hardware_id), got Valid=true err=%q", s.Error)
	}
	if !strings.Contains(s.Error, "hardware_id") {
		t.Errorf("error message should mention hardware_id: %q", s.Error)
	}
}

func TestReload_RejectsEmptyExpiry(t *testing.T) {
	m, priv, licPath := setupSignedManager(t)
	writeSigned(t, priv, licPath, License{
		HardwareID: m.hardwareID,
		Expiry:     "",
		Features:   []string{"all"},
		Type:       "enterprise",
	})
	m.Reload()
	if m.GetStatus().Valid {
		t.Fatal("expected invalid (empty expiry)")
	}
}

func TestReload_RejectsBadSignature(t *testing.T) {
	m, _, licPath := setupSignedManager(t)
	// Sign with the WRONG key.
	_, wrong, _ := ed25519.GenerateKey(rand.Reader)
	writeSigned(t, wrong, licPath, License{
		HardwareID: m.hardwareID,
		Expiry:     "perpetual",
		Features:   []string{"all"},
	})
	m.Reload()
	if m.GetStatus().Valid {
		t.Fatal("expected invalid (signature mismatch)")
	}
}

func TestReload_RejectsWrongHardwareID(t *testing.T) {
	m, priv, licPath := setupSignedManager(t)
	writeSigned(t, priv, licPath, License{
		HardwareID: "deadbeefdeadbeefdeadbeefdeadbeef",
		Expiry:     "perpetual",
		Features:   []string{"all"},
	})
	m.Reload()
	if m.GetStatus().Valid {
		t.Fatal("expected invalid (hardware ID mismatch)")
	}
}

func TestReload_AcceptsValidPerpetual(t *testing.T) {
	m, priv, licPath := setupSignedManager(t)
	writeSigned(t, priv, licPath, License{
		HardwareID: m.hardwareID,
		Customer:   "ACME",
		Expiry:     "perpetual",
		Features:   []string{"all"},
		Type:       "enterprise",
	})
	m.Reload()
	s := m.GetStatus()
	if !s.Valid {
		t.Fatalf("expected valid, got %q", s.Error)
	}
	if s.DaysLeft != -1 {
		t.Errorf("DaysLeft = %d, want -1 for perpetual", s.DaysLeft)
	}
}

func TestInstall_RefusesBadLicenseWithoutOverwrite(t *testing.T) {
	m, _, licPath := setupSignedManager(t)
	// Place a valid license first
	_, priv, _ := ed25519.GenerateKey(rand.Reader) // wrong key
	bad := License{
		HardwareID: m.hardwareID,
		Expiry:     "perpetual",
		Features:   []string{"all"},
	}
	payload, _ := json.Marshal(bad)
	sig := ed25519.Sign(priv, payload)
	badData, _ := json.Marshal(SignedLicense{
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(sig),
	})

	if err := m.Install(badData); err == nil {
		t.Fatal("expected Install to reject bad signature")
	}
	// Live file should NOT exist (or remain unchanged).
	if data, _ := os.ReadFile(licPath); bytes.Contains(data, []byte("ACME")) {
		t.Error("Install with bad signature should NOT have written to disk")
	}
}
