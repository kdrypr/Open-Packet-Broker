// Package masking provides packet data anonymization/masking configuration.
//
// Supports:
//   - IP anonymization (zero last octet, hash-based, or full mask)
//   - MAC anonymization (randomize OUI or full)
//   - Payload scrubbing (zero out L4+ payload, keep headers)
//   - PII pattern masking (email, credit card regex replacement)
//
// The actual masking runs in the C binary. This package writes masking.conf.
package masking

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
)

// ── Types ─────────────────────────────────────────────────────────────────────

// Rule represents a masking/anonymization rule.
type Rule struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`        // "ip", "mac", "payload", "regex"
	Method      string `json:"method"`      // type-specific method
	Pattern     string `json:"pattern"`     // regex pattern (for type=regex)
	Replacement string `json:"replacement"` // replacement string
	Port        string `json:"port"`        // apply to specific port ("" = all)
	Enabled     bool   `json:"enabled"`
	Created     string `json:"created"`
}

// Methods per type:
//   ip:      "zero_last" (x.x.x.0), "hash" (deterministic), "full" (0.0.0.0)
//   mac:     "randomize_oui" (keep vendor), "full" (00:00:00:00:00:00)
//   payload: "zero" (zero L4+ payload), "truncate" (keep N bytes of header)
//   regex:   custom pattern+replacement (e.g., email, credit card)

// Preset masking templates for quick setup.
var Presets = []struct {
	Name    string
	Type    string
	Method  string
	Pattern string
	Replace string
	Desc    string
}{
	{"Anonymize Source IP", "ip", "zero_last", "", "", "Replace last octet with 0 (e.g., 192.168.1.100 → 192.168.1.0)"},
	{"Anonymize Dest IP", "ip", "hash", "", "", "Deterministic hash-based IP replacement (reversible with key)"},
	{"Full IP Mask", "ip", "full", "", "", "Replace all IPs with 0.0.0.0"},
	{"Randomize MAC OUI", "mac", "randomize_oui", "", "", "Replace vendor portion of MAC, keep format"},
	{"Full MAC Mask", "mac", "full", "", "", "Replace all MACs with 00:00:00:00:00:00"},
	{"Zero Payload", "payload", "zero", "", "", "Zero out all data after transport header (headers preserved)"},
	{"Mask Email", "regex", "", `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`, "***@***.***", "Replace email addresses in payload"},
	{"Mask Credit Card", "regex", "", `\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`, "****-****-****-****", "Replace credit card numbers"},
	{"Mask Phone", "regex", "", `\b\d{3}[\s.-]?\d{3}[\s.-]?\d{4}\b`, "***-***-****", "Replace US phone numbers"},
}

// ── Store ─────────────────────────────────────────────────────────────────────

// Store manages masking rules in SQLite and writes config for C binary.
type Store struct {
	db       *sql.DB
	confPath string
}

// New creates the masking store and runs migrations.
func New(db *sql.DB, confPath string) (*Store, error) {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS masking_rules (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			name        TEXT NOT NULL,
			type        TEXT NOT NULL,
			method      TEXT NOT NULL DEFAULT '',
			pattern     TEXT NOT NULL DEFAULT '',
			replacement TEXT NOT NULL DEFAULT '',
			port        TEXT NOT NULL DEFAULT '',
			enabled     INTEGER NOT NULL DEFAULT 1,
			created     DATETIME DEFAULT CURRENT_TIMESTAMP
		)`)
	if err != nil {
		return nil, err
	}
	return &Store{db: db, confPath: confPath}, nil
}

func (s *Store) Create(name, typ, method, pattern, replacement, port string) error {
	if name == "" || typ == "" {
		return errors.New("name and type required")
	}
	if typ == "regex" && pattern == "" {
		return errors.New("regex pattern required for regex type")
	}
	_, err := s.db.Exec(`INSERT INTO masking_rules (name, type, method, pattern, replacement, port) VALUES (?,?,?,?,?,?)`,
		name, typ, method, pattern, replacement, port)
	if err == nil {
		s.writeConf()
	}
	return err
}

func (s *Store) List() ([]Rule, error) {
	rows, err := s.db.Query(`SELECT id, name, type, method, pattern, replacement, port, enabled, created FROM masking_rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		var r Rule
		var en int
		if err := rows.Scan(&r.ID, &r.Name, &r.Type, &r.Method, &r.Pattern, &r.Replacement, &r.Port, &en, &r.Created); err != nil {
			return nil, err
		}
		r.Enabled = en == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) Delete(id int64) error {
	_, err := s.db.Exec(`DELETE FROM masking_rules WHERE id=?`, id)
	if err == nil {
		s.writeConf()
	}
	return err
}

func (s *Store) Toggle(id int64) error {
	_, err := s.db.Exec(`UPDATE masking_rules SET enabled=CASE WHEN enabled=1 THEN 0 ELSE 1 END WHERE id=?`, id)
	if err == nil {
		s.writeConf()
	}
	return err
}

// writeConf writes masking.conf for the C binary.
// Format: type,method,pattern,replacement,port
func (s *Store) writeConf() {
	rules, _ := s.List()
	var lines []string
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		port := r.Port
		if port == "" {
			port = "*"
		}
		line := fmt.Sprintf("%s,%s,%s,%s,%s", r.Type, r.Method, r.Pattern, r.Replacement, port)
		lines = append(lines, line)
	}
	content := strings.Join(lines, "\n")
	if content != "" {
		content += "\n"
	}
	os.WriteFile(s.confPath, []byte(content), 0600)
}
