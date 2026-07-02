// Package dedup manages packet deduplication configuration.
// The actual dedup logic runs in the C binary using a hash table.
// This package writes dedup.conf for the C binary to read.
package dedup

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Config represents dedup settings for a port.
type Config struct {
	ID        int64  `json:"id"`
	Port      string `json:"port"` // interface name, "" = global
	Enabled   bool   `json:"enabled"`
	WindowMS  int    `json:"window_ms"`  // time window for duplicate detection
	HashBytes int    `json:"hash_bytes"` // how many bytes of packet to hash
	Created   string `json:"created"`
}

// Store manages dedup configuration in SQLite.
type Store struct {
	db       *sql.DB
	confPath string // dedup.conf path for C binary
}

// New creates the dedup store and runs migrations.
func New(db *sql.DB, confPath string) (*Store, error) {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS dedup_config (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			port       TEXT NOT NULL DEFAULT '',
			enabled    INTEGER NOT NULL DEFAULT 1,
			window_ms  INTEGER NOT NULL DEFAULT 100,
			hash_bytes INTEGER NOT NULL DEFAULT 128,
			created    DATETIME DEFAULT CURRENT_TIMESTAMP
		)`)
	if err != nil {
		return nil, err
	}
	return &Store{db: db, confPath: confPath}, nil
}

func (s *Store) Create(port string, windowMS, hashBytes int) (int64, error) {
	if windowMS <= 0 {
		windowMS = 100
	}
	if hashBytes <= 0 {
		hashBytes = 128
	}
	res, err := s.db.Exec(`INSERT INTO dedup_config (port, window_ms, hash_bytes) VALUES (?,?,?)`,
		port, windowMS, hashBytes)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	s.writeConf()
	return id, nil
}

func (s *Store) List() ([]Config, error) {
	rows, err := s.db.Query(`SELECT id, port, enabled, window_ms, hash_bytes, created FROM dedup_config ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Config
	for rows.Next() {
		var c Config
		var en int
		if err := rows.Scan(&c.ID, &c.Port, &en, &c.WindowMS, &c.HashBytes, &c.Created); err != nil {
			return nil, err
		}
		c.Enabled = en == 1
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) Delete(id int64) error {
	res, err := s.db.Exec(`DELETE FROM dedup_config WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("not found")
	}
	s.writeConf()
	return nil
}

func (s *Store) Toggle(id int64) error {
	_, err := s.db.Exec(`UPDATE dedup_config SET enabled=CASE WHEN enabled=1 THEN 0 ELSE 1 END WHERE id=?`, id)
	if err == nil {
		s.writeConf()
	}
	return err
}

// writeConf writes dedup.conf for the C binary.
// Format: one line per entry: port,enabled,window_ms,hash_bytes
// Global entry has port = "*"
func (s *Store) writeConf() {
	configs, _ := s.List()
	var lines []string
	for _, c := range configs {
		port := c.Port
		if port == "" {
			port = "*"
		}
		en := 0
		if c.Enabled {
			en = 1
		}
		lines = append(lines, fmt.Sprintf("%s,%d,%d,%d", port, en, c.WindowMS, c.HashBytes))
	}
	content := strings.Join(lines, "\n")
	if content != "" {
		content += "\n"
	}
	os.WriteFile(s.confPath, []byte(content), 0600)
}
