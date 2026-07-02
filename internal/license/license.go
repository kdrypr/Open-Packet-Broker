// Package license provides hardware-locked license key management.
//
// License flow:
//  1. Device generates a Hardware ID (fingerprint of MAC + CPU + disk)
//  2. Vendor signs a license JSON containing HardwareID + expiry + features
//  3. Device verifies signature using the embedded public key
//
// License format (base64-encoded JSON + Ed25519 signature):
//
//	{ "hardware_id": "...", "customer": "...", "expiry": "2027-01-01",
//	  "features": ["mirror","ssl","cluster"], "max_ports": 24, "type": "enterprise" }
//
// Key generation (offline, vendor side):
//
//	ed25519.GenerateKey() → save private key securely
//	Embed public key in this binary
package license

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// ── Types ─────────────────────────────────────────────────────────────────────

// License holds the decoded license claims.
type License struct {
	HardwareID string   `json:"hardware_id"`
	Customer   string   `json:"customer"`
	Expiry     string   `json:"expiry"`    // "2027-01-01" or "perpetual"
	Features   []string `json:"features"`  // ["mirror","ssl","cluster","dedup","throttle"] or ["all"]
	MaxPorts   int      `json:"max_ports"` // 0 = unlimited
	Type       string   `json:"type"`      // "trial","standard","enterprise"
	IssuedAt   string   `json:"issued_at"`
}

// Status represents the current license state shown in the UI.
type Status struct {
	Valid      bool     `json:"valid"`
	License    *License `json:"license,omitempty"`
	HardwareID string   `json:"hardware_id"`
	Error      string   `json:"error,omitempty"`
	DaysLeft   int      `json:"days_left"` // -1 = perpetual, 0 = expired
	Expired    bool     `json:"expired"`
}

// SignedLicense is the wire format: base64(json) + "." + base64(signature)
type SignedLicense struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// ── Embedded public key ───────────────────────────────────────────────────────
// Replace this with your actual vendor public key (32 bytes, hex-encoded).
// Generate with: go run cmd/keygen/main.go

var vendorPubKeyHex = "0000000000000000000000000000000000000000000000000000000000000000"

// ── Manager ───────────────────────────────────────────────────────────────────

// Manager handles license verification and feature gating.
type Manager struct {
	mu         sync.RWMutex
	licPath    string
	status     Status
	hardwareID string
	pubKey     ed25519.PublicKey
}

// ErrVendorKeyInvalid indicates the embedded vendor pubkey is the wrong
// length (e.g. a build-time typo / dropped character). Callers MUST
// treat this as a fatal startup error — silently falling back to "no
// signature check" mode would let an attacker upload any unsigned
// license and unlock the product.
var ErrVendorKeyInvalid = errors.New("license: embedded vendor pubkey has invalid length — refusing to start")

// NewManager creates a license manager and loads the current license.
//
// Returns ErrVendorKeyInvalid if vendorPubKeyHex is missing/malformed.
// Production builds embed a real 64-hex-char (32-byte) key; if a build
// typo drops a character we want a loud crash, not a silent open-door.
func NewManager(licPath string) (*Manager, error) {
	pubKeyBytes, err := hex.DecodeString(vendorPubKeyHex)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		return nil, ErrVendorKeyInvalid
	}
	m := &Manager{
		licPath:    licPath,
		hardwareID: GenerateHardwareID(),
		pubKey:     ed25519.PublicKey(pubKeyBytes),
	}
	m.Reload()
	return m, nil
}

// ── Hardware Fingerprint ──────────────────────────────────────────────────────

// GenerateHardwareID creates a deterministic fingerprint from system properties.
func GenerateHardwareID() string {
	var parts []string

	// MAC addresses (sorted, stable)
	ifaces, _ := net.Interfaces()
	var macs []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		mac := iface.HardwareAddr.String()
		if mac != "" {
			macs = append(macs, mac)
		}
	}
	sort.Strings(macs)
	parts = append(parts, macs...)

	// Machine ID (Linux)
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/etc/machine-id"); err == nil {
			parts = append(parts, strings.TrimSpace(string(data)))
		} else if data, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil {
			parts = append(parts, strings.TrimSpace(string(data)))
		}
	}

	// Product serial (Linux)
	if data, err := os.ReadFile("/sys/class/dmi/id/product_serial"); err == nil {
		s := strings.TrimSpace(string(data))
		if s != "" && s != "To Be Filled By O.E.M." {
			parts = append(parts, s)
		}
	}

	// Fallback: hostname
	if len(parts) == 0 {
		h, _ := os.Hostname()
		parts = append(parts, h, runtime.GOARCH, runtime.GOOS)
	}

	hash := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(hash[:16]) // 32-char hex
}

// ── License operations ────────────────────────────────────────────────────────

// Reload reads and verifies the license file.
func (m *Manager) Reload() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.status = Status{HardwareID: m.hardwareID}

	data, err := os.ReadFile(m.licPath)
	if err != nil {
		m.status.Error = "No license file found"
		return
	}

	var signed SignedLicense
	if err := json.Unmarshal(data, &signed); err != nil {
		m.status.Error = "Invalid license format"
		return
	}

	// Decode payload
	payloadBytes, err := base64.StdEncoding.DecodeString(signed.Payload)
	if err != nil {
		m.status.Error = "Invalid license payload encoding"
		return
	}

	// Verify signature
	sigBytes, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil {
		m.status.Error = "Invalid signature encoding"
		return
	}

	// Signature MUST verify. NewManager already rejected a malformed
	// embedded pubkey at startup, so we don't have a "dev mode" fallback
	// here — a license that doesn't verify is simply invalid.
	if !ed25519.Verify(m.pubKey, payloadBytes, sigBytes) {
		m.status.Error = "Invalid license signature"
		return
	}

	// Decode license claims
	var lic License
	if err := json.Unmarshal(payloadBytes, &lic); err != nil {
		m.status.Error = "Invalid license data"
		return
	}

	// Hardware-binding is mandatory — empty HardwareID means the license
	// was issued without a target device, which would let one .key file
	// unlock every customer's appliance.
	if lic.HardwareID == "" {
		m.status.Error = "License missing hardware_id (must be device-bound)"
		return
	}
	if lic.HardwareID != m.hardwareID {
		m.status.Error = fmt.Sprintf("License is for hardware %s, this device is %s",
			lic.HardwareID[:8]+"...", m.hardwareID[:8]+"...")
		return
	}

	// Expiry is also mandatory — empty was previously treated as perpetual,
	// which could silently happen via dropped JSON field. Require explicit
	// "perpetual" if that's the intent.
	if lic.Expiry == "" {
		m.status.Error = "License missing expiry (use \"perpetual\" for unlimited)"
		return
	}
	if lic.Expiry != "perpetual" {
		exp, err := time.Parse("2006-01-02", lic.Expiry)
		if err != nil {
			m.status.Error = "Invalid expiry date"
			return
		}
		days := int(time.Until(exp).Hours() / 24)
		m.status.DaysLeft = days
		if days < 0 {
			m.status.Expired = true
			m.status.Error = "License expired on " + lic.Expiry
			m.status.License = &lic
			return
		}
	} else {
		m.status.DaysLeft = -1 // perpetual
	}

	m.status.Valid = true
	m.status.License = &lic
}

// GetStatus returns the current license status.
func (m *Manager) GetStatus() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

// VerifyKey returns the embedded Ed25519 vendor public key. Other
// packages (firmware signing) reuse this so vendors only need one
// signing identity for both license and firmware.
func (m *Manager) VerifyKey() ed25519.PublicKey {
	return m.pubKey
}

// Install saves a new license file and reloads, but only after the
// candidate license verifies cleanly against the current device. This
// prevents a bad upload from clobbering the working .key on disk and
// leaving the appliance unlicensed at next reboot.
func (m *Manager) Install(licenseData []byte) error {
	// Validate JSON structure first
	var signed SignedLicense
	if err := json.Unmarshal(licenseData, &signed); err != nil {
		return errors.New("invalid license file format")
	}
	if signed.Payload == "" || signed.Signature == "" {
		return errors.New("license file missing payload or signature")
	}

	// Dry-run verify before touching disk: redirect Reload at a temp file
	// (do not move the live file yet). Implemented via a temp manager so
	// the live status isn't mutated by a bad upload.
	tmp := &Manager{
		licPath:    m.licPath + ".validate.tmp",
		hardwareID: m.hardwareID,
		pubKey:     m.pubKey,
	}
	if err := os.WriteFile(tmp.licPath, licenseData, 0600); err != nil {
		return fmt.Errorf("failed to write temp license: %w", err)
	}
	tmp.Reload()
	tmpStatus := tmp.GetStatus()
	_ = os.Remove(tmp.licPath)
	if !tmpStatus.Valid {
		if tmpStatus.Error != "" {
			return errors.New(tmpStatus.Error)
		}
		return errors.New("license verification failed")
	}

	// Verified — atomically replace the live file.
	if err := os.WriteFile(m.licPath, licenseData, 0600); err != nil {
		return fmt.Errorf("failed to save license: %w", err)
	}
	m.Reload()
	return nil
}

// HasFeature checks if a feature is licensed.
func (m *Manager) HasFeature(feature string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.status.Valid || m.status.License == nil {
		return false
	}
	for _, f := range m.status.License.Features {
		if f == "all" || f == feature {
			return true
		}
	}
	return false
}

// IsValid returns true if a valid, non-expired license is loaded.
func (m *Manager) IsValid() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status.Valid
}

// MaxPorts returns the licensed port limit (0 = unlimited).
func (m *Manager) MaxPorts() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.status.License != nil {
		return m.status.License.MaxPorts
	}
	return 0
}

// ── License Generation (vendor-side utility) ──────────────────────────────────

// GenerateLicense creates a signed license. Used offline by the vendor.
// privateKey must be a 64-byte Ed25519 private key.
func GenerateLicense(privateKey ed25519.PrivateKey, lic License) ([]byte, error) {
	if lic.IssuedAt == "" {
		lic.IssuedAt = time.Now().UTC().Format("2006-01-02")
	}
	payload, err := json.Marshal(lic)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(privateKey, payload)

	signed := SignedLicense{
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}
	return json.MarshalIndent(signed, "", "  ")
}

// GenerateKeyPair creates a new Ed25519 key pair for license signing.
func GenerateKeyPair() (pubHex, privHex string, err error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(pub), hex.EncodeToString(priv), nil
}
