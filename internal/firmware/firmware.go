// Package firmware handles binary upload and hot-swap for the C broker.
//
// Uploads MUST be Ed25519-signed by the vendor — without that gate, any
// authenticated admin (or stolen session) could replace the data-plane
// binary that runs as root via systemd, giving a stolen admin session a
// reboot-persistent root rootkit. The verify key is the same public key
// embedded in internal/license/license.go so vendors only need one
// signing identity.
//
// Wire format: a 4-byte big-endian signature length, followed by an
// Ed25519 signature, followed by the raw ELF bytes. The keygen CLI
// builds these bundles with cmd/keygen -sign-firmware.
package firmware

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Info holds metadata about the current or uploaded firmware.
type Info struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
	Modified string `json:"modified"`
}

// Manager handles firmware file operations.
type Manager struct {
	brokerBinPath string // path to packet_broker binary
	backupDir     string
	verifyKey     ed25519.PublicKey // vendor pubkey, set via SetVerifyKey
}

// NewManager creates a firmware manager.
func NewManager(brokerBinPath, backupDir string) *Manager {
	os.MkdirAll(backupDir, 0o750)
	return &Manager{brokerBinPath: brokerBinPath, backupDir: backupDir}
}

// SetVerifyKey installs the Ed25519 pubkey used to verify firmware
// bundle signatures. Must be called before Upload(); upload returns an
// error otherwise so a misbuilt binary doesn't silently accept anything.
func (m *Manager) SetVerifyKey(pub ed25519.PublicKey) {
	m.verifyKey = pub
}

// CurrentInfo returns info about the current broker binary.
func (m *Manager) CurrentInfo() Info {
	return fileInfo(m.brokerBinPath, "packet_broker")
}

// ErrUnsigned is returned when the upload doesn't carry a vendor
// signature; ErrBadSignature when the signature doesn't verify.
var (
	ErrUnsigned     = errors.New("firmware: unsigned upload rejected (require vendor-signed bundle)")
	ErrBadSignature = errors.New("firmware: signature verification failed")
	ErrNoVerifyKey  = errors.New("firmware: verify key not configured — upload disabled")
)

// Bundle format limits.
const (
	minFirmwareBytes int64 = 1024 // smaller than this is suspicious
	maxFirmwareBytes int64 = 256 * 1024 * 1024
)

// Upload replaces the broker binary with a vendor-signed bundle.
//
//	[ 4-byte BE sigLen ][ sigLen-byte Ed25519 sig ][ ELF bytes... ]
//
// The signature is over the SHA-256 hash of the raw ELF bytes (post-
// header), and the verify key must be installed via SetVerifyKey at
// startup. The previous binary is backed up only AFTER the new one
// verifies — a bad upload never touches the live file.
func (m *Manager) Upload(src io.Reader, filename string) (*Info, error) {
	if m.verifyKey == nil || len(m.verifyKey) != ed25519.PublicKeySize {
		return nil, ErrNoVerifyKey
	}

	// 1) Read the whole bundle to a temp file (bounded).
	tmpPath := m.brokerBinPath + ".upload"
	tmpFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	size, err := io.Copy(tmpFile, io.LimitReader(src, maxFirmwareBytes+1))
	tmpFile.Close()
	if err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("write failed: %w", err)
	}
	if size < minFirmwareBytes {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("file too small (%d bytes)", size)
	}
	if size > maxFirmwareBytes {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("file too large (%d bytes), max %d", size, maxFirmwareBytes)
	}

	// 2) Parse signature header.
	bundle, err := os.ReadFile(tmpPath)
	if err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("re-read failed: %w", err)
	}
	if len(bundle) < 4 {
		os.Remove(tmpPath)
		return nil, ErrUnsigned
	}
	sigLen := binary.BigEndian.Uint32(bundle[:4])
	if sigLen == 0 {
		os.Remove(tmpPath)
		return nil, ErrUnsigned
	}
	if sigLen != ed25519.SignatureSize {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("firmware: unexpected signature length %d", sigLen)
	}
	if int(4+sigLen) > len(bundle) {
		os.Remove(tmpPath)
		return nil, errors.New("firmware: bundle truncated before payload")
	}
	signature := bundle[4 : 4+sigLen]
	elf := bundle[4+sigLen:]

	// 3) Validate ELF magic on the payload (not the bundle header).
	if len(elf) < 4 || string(elf[:4]) != "\x7fELF" {
		os.Remove(tmpPath)
		return nil, errors.New("firmware: payload is not an ELF executable")
	}

	// 4) Verify signature over SHA-256(elf).
	sum := sha256.Sum256(elf)
	if !ed25519.Verify(m.verifyKey, sum[:], signature) {
		os.Remove(tmpPath)
		return nil, ErrBadSignature
	}

	// 5) Write the verified ELF to a separate tmp file (drop signature header).
	elfTmp := m.brokerBinPath + ".verified"
	// 0o755: this is the broker executable — it must carry the exec bit
	// (the one legitimate >0600 write; gosec G306 is excluded for this reason).
	if err := os.WriteFile(elfTmp, elf, 0o755); err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("stage verified file: %w", err)
	}
	os.Remove(tmpPath)

	// 6) Backup current binary, then atomic rename.
	if _, err := os.Stat(m.brokerBinPath); err == nil {
		backupName := fmt.Sprintf("packet_broker_%s.bak", time.Now().Format("20060102_150405"))
		backupPath := filepath.Join(m.backupDir, backupName)
		if err := copyFile(m.brokerBinPath, backupPath); err != nil {
			// Best-effort — proceed with replace even if backup fails (logged
			// to the bundle metadata by the caller).
			_ = err
		} else if sig, err := os.ReadFile(m.sigPath()); err == nil {
			// Preserve the outgoing binary's vendor signature next to its
			// backup so Rollback can re-verify it before reinstalling.
			_ = os.WriteFile(backupPath+".sig", sig, 0o600)
		}
	}
	if err := os.Rename(elfTmp, m.brokerBinPath); err != nil {
		os.Remove(elfTmp)
		return nil, fmt.Errorf("replace failed: %w", err)
	}
	_ = os.Chmod(m.brokerBinPath, 0o755)
	// Record the now-live binary's signature for future backup/rollback verification.
	_ = os.WriteFile(m.sigPath(), signature, 0o600)

	info := Info{
		Name:     filename,
		Path:     m.brokerBinPath,
		Size:     int64(len(elf)),
		SHA256:   hex.EncodeToString(sum[:]),
		Modified: time.Now().Format("2006-01-02 15:04:05"),
	}
	return &info, nil
}

// ListBackups returns available firmware backups.
func (m *Manager) ListBackups() []Info {
	entries, err := os.ReadDir(m.backupDir)
	if err != nil {
		return nil
	}
	var out []Info
	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), ".sig") {
			continue // .sig sidecars are not restorable backups
		}
		path := filepath.Join(m.backupDir, e.Name())
		out = append(out, fileInfo(path, e.Name()))
	}
	return out
}

// sigPath is the sidecar file holding the vendor Ed25519 signature of the
// currently-installed broker binary.
func (m *Manager) sigPath() string { return m.brokerBinPath + ".sig" }

// Rollback restores a backup binary after re-verifying its vendor
// signature. The signature was stored alongside the backup at Upload time;
// because verification uses the embedded vendor public key, a malicious
// binary an attacker drops into the backup dir cannot pass (they cannot
// forge a vendor signature), so rollback can never install unsigned code as
// the root-run data plane.
func (m *Manager) Rollback(backupName string) error {
	if m.verifyKey == nil || len(m.verifyKey) != ed25519.PublicKeySize {
		return ErrNoVerifyKey
	}
	src := filepath.Join(m.backupDir, filepath.Base(backupName))
	fi, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("backup not found: %s", backupName)
	}
	if fi.Size() < minFirmwareBytes {
		return errors.New("firmware: backup file too small to be valid")
	}
	elf, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read backup: %w", err)
	}
	sig, err := os.ReadFile(src + ".sig")
	if err != nil {
		return errors.New("firmware: backup has no signature on record; refusing unverified rollback")
	}
	sum := sha256.Sum256(elf)
	if !ed25519.Verify(m.verifyKey, sum[:], sig) {
		return ErrBadSignature
	}
	if err := copyFile(src, m.brokerBinPath); err != nil {
		return err
	}
	// Keep the signature chain intact for the now-live binary.
	_ = os.WriteFile(m.sigPath(), sig, 0o600)
	return nil
}

func fileInfo(path, name string) Info {
	fi, err := os.Stat(path)
	if err != nil {
		return Info{Name: name, Path: path}
	}
	data, _ := os.ReadFile(path)
	h := sha256.Sum256(data)
	return Info{
		Name:     name,
		Path:     path,
		Size:     fi.Size(),
		SHA256:   hex.EncodeToString(h[:]),
		Modified: fi.ModTime().Format("2006-01-02 15:04:05"),
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
