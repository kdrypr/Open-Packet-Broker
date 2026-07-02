// Package mirror manages traffic mirroring (SPAN) sessions.
// A mirror session copies ALL traffic from a source port to N dest ports.
package mirror

import (
	"database/sql"
	"errors"
	"strings"
)

// Session represents a mirror/SPAN configuration.
type Session struct {
	ID       int64    `json:"id"`
	Name     string   `json:"name"`
	SrcPort  string   `json:"src_port"`
	DstPorts []string `json:"dst_ports"`
	Enabled  bool     `json:"enabled"`
	Created  string   `json:"created"`
}

// Store manages mirror sessions in SQLite.
type Store struct{ db *sql.DB }

// New creates the mirror store and runs migrations.
func New(db *sql.DB) (*Store, error) {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS mirror_sessions (
			id        INTEGER PRIMARY KEY AUTOINCREMENT,
			name      TEXT NOT NULL,
			src_port  TEXT NOT NULL,
			dst_ports TEXT NOT NULL,
			enabled   INTEGER NOT NULL DEFAULT 1,
			created   DATETIME DEFAULT CURRENT_TIMESTAMP
		)`)
	if err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Create(name, srcPort string, dstPorts []string) (int64, error) {
	if name == "" || srcPort == "" || len(dstPorts) == 0 {
		return 0, errors.New("name, source port, and at least one dest port required")
	}
	res, err := s.db.Exec(`INSERT INTO mirror_sessions (name, src_port, dst_ports) VALUES (?,?,?)`,
		name, srcPort, strings.Join(dstPorts, ","))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) List() ([]Session, error) {
	rows, err := s.db.Query(`SELECT id, name, src_port, dst_ports, enabled, created FROM mirror_sessions ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		var m Session
		var dsts string
		var en int
		if err := rows.Scan(&m.ID, &m.Name, &m.SrcPort, &dsts, &en, &m.Created); err != nil {
			return nil, err
		}
		m.DstPorts = strings.Split(dsts, ",")
		m.Enabled = en == 1
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) Delete(id int64) error {
	_, err := s.db.Exec(`DELETE FROM mirror_sessions WHERE id=?`, id)
	return err
}

func (s *Store) Toggle(id int64) error {
	_, err := s.db.Exec(`UPDATE mirror_sessions SET enabled=CASE WHEN enabled=1 THEN 0 ELSE 1 END WHERE id=?`, id)
	return err
}

// GenerateRuleCSV returns rules.conf lines for active mirror sessions.
// Each src→dst pair becomes a rule with no filters (forward all traffic).
func (s *Store) GenerateRuleCSV() []string {
	sessions, _ := s.List()
	var lines []string
	for _, m := range sessions {
		if !m.Enabled {
			continue
		}
		for _, dst := range m.DstPorts {
			dst = strings.TrimSpace(dst)
			if dst == "" {
				continue
			}
			// 22-field CSV: all filters = 0/empty = match everything
			fields := []string{
				m.SrcPort, "0", "0", "0", "0", "0", "0", dst,
				"1", "0", "none", "0", "0",
				"0", "0", "0", "0", "",
				"0", "0", "", "0",
			}
			lines = append(lines, strings.Join(fields, ","))
		}
	}
	return lines
}
