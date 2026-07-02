// Package auditlog records who changed what and when.
package auditlog

import (
	"database/sql"
	"time"
)

type Entry struct {
	ID        int64  `json:"id"`
	Timestamp string `json:"timestamp"`
	Username  string `json:"username"`
	Action    string `json:"action"`
	Detail    string `json:"detail"`
	IP        string `json:"ip"`
}

type Store struct{ db *sql.DB }

func New(db *sql.DB) (*Store, error) {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		username TEXT NOT NULL,
		action TEXT NOT NULL,
		detail TEXT NOT NULL DEFAULT '',
		ip TEXT NOT NULL DEFAULT ''
	)`)
	if err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Log(username, action, detail, ip string) {
	s.db.Exec(`INSERT INTO audit_log (username, action, detail, ip) VALUES (?,?,?,?)`,
		username, action, detail, ip)
	// Prune: keep last 5000 entries
	s.db.Exec(`DELETE FROM audit_log WHERE id NOT IN (SELECT id FROM audit_log ORDER BY id DESC LIMIT 5000)`)
}

func (s *Store) List(limit int) ([]Entry, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT id, timestamp, username, action, detail, ip FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		rows.Scan(&e.ID, &e.Timestamp, &e.Username, &e.Action, &e.Detail, &e.IP)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) Since(t time.Time) ([]Entry, error) {
	rows, err := s.db.Query(`SELECT id, timestamp, username, action, detail, ip FROM audit_log WHERE timestamp > ? ORDER BY id DESC`, t.Format("2006-01-02 15:04:05"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		rows.Scan(&e.ID, &e.Timestamp, &e.Username, &e.Action, &e.Detail, &e.IP)
		out = append(out, e)
	}
	return out, rows.Err()
}
