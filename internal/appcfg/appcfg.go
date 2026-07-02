// Package appcfg stores appliance-level settings the operator manages from the
// UI: product branding (name + logo) and the TLS/FQDN identity. It is a single
// row in SQLite, shared with the other stores via the same *sql.DB handle.
package appcfg

import (
	"database/sql"
	"strings"
	"sync"
)

// DefaultProductName is used until the operator brands the appliance.
const DefaultProductName = "Packet Broker"

// Config is the appliance settings snapshot.
type Config struct {
	ProductName string `json:"product_name"`
	LogoPath    string `json:"logo_path"` // relative path under the static dir, "" = built-in icon
	FQDN        string `json:"fqdn"`      // appliance hostname shown on the cert / UI
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
			fqdn         TEXT NOT NULL DEFAULT ''
		)`)
	if err != nil {
		return nil, err
	}
	_, _ = db.Exec(`INSERT OR IGNORE INTO app_config (id) VALUES (1)`)
	s := &Store{db: db}
	s.load()
	return s, nil
}

func (s *Store) load() {
	var c Config
	_ = s.db.QueryRow(`SELECT product_name, logo_path, fqdn FROM app_config WHERE id=1`).
		Scan(&c.ProductName, &c.LogoPath, &c.FQDN)
	if strings.TrimSpace(c.ProductName) == "" {
		c.ProductName = DefaultProductName
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

// SetFQDN records the appliance FQDN (used for the self-signed cert / UI).
func (s *Store) SetFQDN(fqdn string) error {
	if _, err := s.db.Exec(`UPDATE app_config SET fqdn=? WHERE id=1`, strings.TrimSpace(fqdn)); err != nil {
		return err
	}
	s.load()
	return nil
}
