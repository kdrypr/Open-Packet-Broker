// Package throttle manages per-port bandwidth rate limiting configuration.
package throttle

import (
	"database/sql"
	"errors"
)

// Config represents a rate limit for a port.
type Config struct {
	ID      int64  `json:"id"`
	Port    string `json:"port"`
	MaxMbps int    `json:"max_mbps"` // 0 = unlimited
	MaxPPS  int    `json:"max_pps"`  // 0 = unlimited
	Enabled bool   `json:"enabled"`
	Created string `json:"created"`
}

// Store manages throttle configs in SQLite.
type Store struct{ db *sql.DB }

// New creates the throttle store and runs migrations.
func New(db *sql.DB) (*Store, error) {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS throttle_config (
			id       INTEGER PRIMARY KEY AUTOINCREMENT,
			port     TEXT NOT NULL,
			max_mbps INTEGER NOT NULL DEFAULT 0,
			max_pps  INTEGER NOT NULL DEFAULT 0,
			enabled  INTEGER NOT NULL DEFAULT 1,
			created  DATETIME DEFAULT CURRENT_TIMESTAMP
		)`)
	if err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Create(port string, maxMbps, maxPPS int) (int64, error) {
	if port == "" {
		return 0, errors.New("port is required")
	}
	res, err := s.db.Exec(`INSERT INTO throttle_config (port, max_mbps, max_pps) VALUES (?,?,?)`,
		port, maxMbps, maxPPS)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) List() ([]Config, error) {
	rows, err := s.db.Query(`SELECT id, port, max_mbps, max_pps, enabled, created FROM throttle_config ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Config
	for rows.Next() {
		var c Config
		var en int
		if err := rows.Scan(&c.ID, &c.Port, &c.MaxMbps, &c.MaxPPS, &en, &c.Created); err != nil {
			return nil, err
		}
		c.Enabled = en == 1
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) Delete(id int64) error {
	_, err := s.db.Exec(`DELETE FROM throttle_config WHERE id=?`, id)
	return err
}

func (s *Store) Toggle(id int64) error {
	_, err := s.db.Exec(`UPDATE throttle_config SET enabled=CASE WHEN enabled=1 THEN 0 ELSE 1 END WHERE id=?`, id)
	return err
}

// GetForPort returns the active throttle for a port, or nil.
func (s *Store) GetForPort(port string) *Config {
	var c Config
	var en int
	err := s.db.QueryRow(`SELECT id, port, max_mbps, max_pps, enabled, created FROM throttle_config WHERE port=? AND enabled=1`, port).
		Scan(&c.ID, &c.Port, &c.MaxMbps, &c.MaxPPS, &en, &c.Created)
	if err != nil {
		return nil
	}
	c.Enabled = en == 1
	return &c
}
