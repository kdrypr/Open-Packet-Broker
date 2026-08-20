// Package appcfg stores appliance-level settings the operator manages from the
// UI: product branding (name + logo), the TLS/FQDN identity, and the
// data-plane auto-start policy. It is a single row in SQLite, shared with the
// other stores via the same *sql.DB handle.
package appcfg

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"
)

// DefaultProductName is used until the operator brands the appliance.
const DefaultProductName = "Packet Broker"

// Data-plane auto-start policies. The appliance's control plane comes up with
// systemd; these decide what happens to the child data-plane process at that
// point.
const (
	AutoStartOff     = "off"     // never start it — the operator uses the UI button
	AutoStartRestore = "restore" // start it if it was running when the UI last exited
	AutoStartAlways  = "always"  // always start it, and restart it if it dies
)

// DefaultAutoStart preserves the operator's last intent across reboots, which
// is what an appliance is expected to do, without ever starting a data plane
// the operator has never started themselves.
const DefaultAutoStart = AutoStartRestore

// Desired-state values: the operator's last explicit start/stop intent, which
// outlives the process (unlike packet_broker.status, which records what is
// actually running right now).
const (
	StateRunning = "running"
	StateStopped = "stopped"
)

// NormalizeAutoStart maps operator input (UI select, PB_AUTOSTART env var) onto
// a policy constant, returning "" when the value isn't recognised so callers
// can tell "not set / invalid" from a deliberate "off".
func NormalizeAutoStart(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case AutoStartOff, "0", "false", "no", "never":
		return AutoStartOff
	case AutoStartRestore, "last":
		return AutoStartRestore
	case AutoStartAlways, "1", "true", "yes", "on":
		return AutoStartAlways
	}
	return ""
}

// Config is the appliance settings snapshot.
type Config struct {
	ProductName string `json:"product_name"`
	LogoPath    string `json:"logo_path"` // relative path under the static dir, "" = built-in icon
	FQDN        string `json:"fqdn"`      // appliance hostname shown on the cert / UI

	// AutoStart is the data-plane auto-start policy (off | restore | always).
	AutoStart string `json:"auto_start"`
	// DesiredState is the operator's last explicit intent for the data plane
	// (running | stopped), used by the "restore" policy after a reboot.
	DesiredState string `json:"desired_state"`
}

// Store persists appliance settings.
type Store struct {
	db *sql.DB
	mu sync.RWMutex
	c  Config
}

// New creates the store, runs the migration, and loads the current config.
func New(db *sql.DB) (*Store, error) {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS app_config (
			id           INTEGER PRIMARY KEY CHECK (id = 1),
			product_name TEXT NOT NULL DEFAULT '',
			logo_path    TEXT NOT NULL DEFAULT '',
			fqdn         TEXT NOT NULL DEFAULT '',
			auto_start   TEXT NOT NULL DEFAULT '',
			desired_state TEXT NOT NULL DEFAULT ''
		)`)
	if err != nil {
		return nil, err
	}
	// Columns added after the first release. On an appliance that already has
	// the table, CREATE TABLE IF NOT EXISTS is a no-op, so they arrive via
	// ALTER; on a fresh DB the ALTER fails with "duplicate column name" and
	// that error is deliberately ignored.
	for _, stmt := range []string{
		`ALTER TABLE app_config ADD COLUMN auto_start TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE app_config ADD COLUMN desired_state TEXT NOT NULL DEFAULT ''`,
	} {
		_, _ = db.Exec(stmt)
	}
	_, _ = db.Exec(`INSERT OR IGNORE INTO app_config (id) VALUES (1)`)
	s := &Store{db: db}
	s.load()
	return s, nil
}

func (s *Store) load() {
	var c Config
	_ = s.db.QueryRow(`SELECT product_name, logo_path, fqdn, auto_start, desired_state FROM app_config WHERE id=1`).
		Scan(&c.ProductName, &c.LogoPath, &c.FQDN, &c.AutoStart, &c.DesiredState)
	if strings.TrimSpace(c.ProductName) == "" {
		c.ProductName = DefaultProductName
	}
	if c.AutoStart = NormalizeAutoStart(c.AutoStart); c.AutoStart == "" {
		c.AutoStart = DefaultAutoStart
	}
	if c.DesiredState != StateRunning {
		c.DesiredState = StateStopped
	}
	s.mu.Lock()
	s.c = c
	s.mu.Unlock()
}

// Get returns the current config (ProductName never empty).
func (s *Store) Get() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.c
}

// SetProductName updates the displayed product name. Empty resets to default.
func (s *Store) SetProductName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		name = DefaultProductName
	}
	if _, err := s.db.Exec(`UPDATE app_config SET product_name=? WHERE id=1`, name); err != nil {
		return err
	}
	s.load()
	return nil
}

// SetLogoPath records the relative static path of an uploaded logo ("" clears).
func (s *Store) SetLogoPath(p string) error {
	if _, err := s.db.Exec(`UPDATE app_config SET logo_path=? WHERE id=1`, p); err != nil {
		return err
	}
	s.load()
	return nil
}

// SetAutoStart records the data-plane auto-start policy. Unrecognised values
// are rejected rather than silently coerced, so a typo in the UI/API can't
// quietly disable auto-start.
func (s *Store) SetAutoStart(mode string) error {
	m := NormalizeAutoStart(mode)
	if m == "" {
		return fmt.Errorf("appcfg: unknown auto-start mode %q", mode)
	}
	if _, err := s.db.Exec(`UPDATE app_config SET auto_start=? WHERE id=1`, m); err != nil {
		return err
	}
	s.load()
	return nil
}

// SetDesiredState records the operator's last explicit data-plane intent. It is
// written when the Start/Stop buttons are used — not by shutdown — so a reboot
// can restore what the operator asked for rather than what a SIGTERM left behind.
func (s *Store) SetDesiredState(state string) error {
	if state != StateRunning {
		state = StateStopped
	}
	if _, err := s.db.Exec(`UPDATE app_config SET desired_state=? WHERE id=1`, state); err != nil {
		return err
	}
	s.load()
	return nil
}

// SetFQDN records the appliance FQDN (used for the self-signed cert / UI).
func (s *Store) SetFQDN(fqdn string) error {
	if _, err := s.db.Exec(`UPDATE app_config SET fqdn=? WHERE id=1`, strings.TrimSpace(fqdn)); err != nil {
		return err
	}
	s.load()
	return nil
}
