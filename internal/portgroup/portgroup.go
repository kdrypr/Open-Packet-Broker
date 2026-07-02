// Package portgroup manages load-balancing port group definitions.
package portgroup

import (
	"database/sql"
	"errors"
	"strings"
)

// ── Types ─────────────────────────────────────────────────────────────────────

// Group represents a load-balancing port group.
type Group struct {
	ID          int64    `json:"id"`
	Name        string   `json:"name"`
	Mode        string   `json:"mode"` // "round-robin" or "hash"
	InputPorts  []string `json:"input_ports"`
	OutputPorts []string `json:"output_ports"`
	Created     string   `json:"created"`
}

// ── Store ─────────────────────────────────────────────────────────────────────

// Store manages port groups in SQLite.
type Store struct {
	db *sql.DB
}

// New creates the port group store and runs migrations.
func New(db *sql.DB) (*Store, error) {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS port_groups (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			name         TEXT NOT NULL,
			mode         TEXT NOT NULL DEFAULT 'round-robin',
			input_ports  TEXT NOT NULL DEFAULT '',
			output_ports TEXT NOT NULL DEFAULT '',
			created      DATETIME DEFAULT CURRENT_TIMESTAMP
		)`)
	if err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

// ── CRUD ──────────────────────────────────────────────────────────────────────

// Create inserts a new port group.
func (s *Store) Create(name, mode string, inputs, outputs []string) (int64, error) {
	if name == "" {
		return 0, errors.New("name is required")
	}
	if mode != "round-robin" && mode != "hash" {
		mode = "round-robin"
	}
	if len(inputs) == 0 || len(outputs) == 0 {
		return 0, errors.New("at least one input and output port required")
	}

	res, err := s.db.Exec(
		`INSERT INTO port_groups (name, mode, input_ports, output_ports) VALUES (?,?,?,?)`,
		name, mode, strings.Join(inputs, ","), strings.Join(outputs, ","),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// List returns all port groups.
func (s *Store) List() ([]Group, error) {
	rows, err := s.db.Query(`SELECT id, name, mode, input_ports, output_ports, created FROM port_groups ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Group
	for rows.Next() {
		var g Group
		var ins, outs string
		if err := rows.Scan(&g.ID, &g.Name, &g.Mode, &ins, &outs, &g.Created); err != nil {
			return nil, err
		}
		if ins != "" {
			g.InputPorts = strings.Split(ins, ",")
		}
		if outs != "" {
			g.OutputPorts = strings.Split(outs, ",")
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// Delete removes a port group.
func (s *Store) Delete(id int64) error {
	res, err := s.db.Exec(`DELETE FROM port_groups WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("port group not found")
	}
	return nil
}

// GenerateRuleLines returns rules.conf-style CSV lines for a port group.
// For round-robin: creates one rule per input→output combination.
func (s *Store) GenerateRuleLines(g Group) []string {
	var lines []string
	for _, in := range g.InputPorts {
		for _, out := range g.OutputPorts {
			// Default rule: forward all traffic
			lines = append(lines, strings.Join([]string{
				in, "0", "0", "0", "0", "0", "0", out,
			}, ","))
		}
	}
	return lines
}
