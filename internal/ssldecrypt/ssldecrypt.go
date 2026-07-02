// Package ssldecrypt manages SSL/TLS inspection chain configurations.
// Defines routing: encrypted_port → decrypt_tool → reinject_port
package ssldecrypt

import (
	"database/sql"
	"errors"
	"strings"
)

// Chain represents an SSL inspection chain.
type Chain struct {
	ID              int64  `json:"id"`
	Name            string `json:"name"`
	EncryptedPort   string `json:"encrypted_port"`    // where encrypted traffic arrives
	DecryptToolPort string `json:"decrypt_tool_port"` // external decryption appliance port
	ReinjectPort    string `json:"reinject_port"`     // where decrypted traffic is sent
	Filter          string `json:"filter"`            // optional BPF filter (e.g. "tcp port 443")
	Enabled         bool   `json:"enabled"`
	Created         string `json:"created"`
}

// Store manages SSL chains in SQLite.
type Store struct{ db *sql.DB }

// New creates the SSL decrypt store and runs migrations.
func New(db *sql.DB) (*Store, error) {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS ssl_chains (
			id                INTEGER PRIMARY KEY AUTOINCREMENT,
			name              TEXT NOT NULL,
			encrypted_port    TEXT NOT NULL,
			decrypt_tool_port TEXT NOT NULL,
			reinject_port     TEXT NOT NULL,
			filter            TEXT NOT NULL DEFAULT '',
			enabled           INTEGER NOT NULL DEFAULT 1,
			created           DATETIME DEFAULT CURRENT_TIMESTAMP
		)`)
	if err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Create(name, encPort, toolPort, reinjectPort, filter string) (int64, error) {
	if name == "" || encPort == "" || toolPort == "" || reinjectPort == "" {
		return 0, errors.New("name and all three ports are required")
	}
	res, err := s.db.Exec(
		`INSERT INTO ssl_chains (name, encrypted_port, decrypt_tool_port, reinject_port, filter) VALUES (?,?,?,?,?)`,
		name, encPort, toolPort, reinjectPort, filter)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) List() ([]Chain, error) {
	rows, err := s.db.Query(`SELECT id, name, encrypted_port, decrypt_tool_port, reinject_port, filter, enabled, created FROM ssl_chains ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Chain
	for rows.Next() {
		var c Chain
		var en int
		if err := rows.Scan(&c.ID, &c.Name, &c.EncryptedPort, &c.DecryptToolPort, &c.ReinjectPort, &c.Filter, &en, &c.Created); err != nil {
			return nil, err
		}
		c.Enabled = en == 1
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) Delete(id int64) error {
	_, err := s.db.Exec(`DELETE FROM ssl_chains WHERE id=?`, id)
	return err
}

func (s *Store) Toggle(id int64) error {
	_, err := s.db.Exec(`UPDATE ssl_chains SET enabled=CASE WHEN enabled=1 THEN 0 ELSE 1 END WHERE id=?`, id)
	return err
}

// GenerateRuleCSV returns rules.conf lines for active SSL chains.
// Each chain produces 2 rules:
//  1. encrypted_port → decrypt_tool_port (send to decryption appliance)
//  2. decrypt_tool_port → reinject_port (return decrypted traffic)
func (s *Store) GenerateRuleCSV() []string {
	chains, _ := s.List()
	var lines []string
	for _, c := range chains {
		if !c.Enabled {
			continue
		}
		// Rule 1: encrypted → tool
		lines = append(lines, makeCSVLine(c.EncryptedPort, c.DecryptToolPort, c.Filter))
		// Rule 2: tool → reinject
		lines = append(lines, makeCSVLine(c.DecryptToolPort, c.ReinjectPort, ""))
	}
	return lines
}

func makeCSVLine(in, out, bpf string) string {
	fields := []string{
		in, "0", "0", "0", "0", "0", "0", out,
		"1", "0", "none", "0", "0",
		"0", "0", "0", "0", bpf,
		"0", "0", "", "0",
	}
	return strings.Join(fields, ",")
}
