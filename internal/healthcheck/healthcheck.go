// Package healthcheck monitors tool output ports and auto-disables rules
// when ports go down, re-enabling when they recover.
package healthcheck

import (
	"database/sql"
	"errors"
	"sync"
	"time"
)

// PortCheck represents a monitored port.
type PortCheck struct {
	ID            int64  `json:"id"`
	Port          string `json:"port"`
	Enabled       bool   `json:"enabled"`      // monitoring enabled
	AutoDisable   bool   `json:"auto_disable"` // auto-disable rules on port down
	Status        string `json:"status"`       // "up", "down", "unknown"
	LastCheck     string `json:"last_check"`
	AffectedRules int    `json:"affected_rules"` // rules currently auto-disabled
}

// LinkInfoReader returns port link status. Key = interface name.
type LinkInfoReader func() map[string]string // iface → "up"/"down"/"unknown"

// RuleToggler enables/disables rules by interface_out.
type RuleToggler interface {
	DisableByOutput(port string) (int, error)
	EnableByOutput(port string) (int, error)
}

// Monitor watches port link states and manages auto-disable.
type Monitor struct {
	db         *sql.DB
	mu         sync.Mutex
	linkReader LinkInfoReader
	toggler    RuleToggler
	stopCh     chan struct{}
}

// New creates the health check monitor and runs migrations.
func New(db *sql.DB, linkReader LinkInfoReader, toggler RuleToggler) (*Monitor, error) {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS health_checks (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			port         TEXT NOT NULL UNIQUE,
			enabled      INTEGER NOT NULL DEFAULT 1,
			auto_disable INTEGER NOT NULL DEFAULT 1,
			last_status  TEXT NOT NULL DEFAULT 'unknown',
			last_check   DATETIME
		)`)
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS auto_disabled_rules (
			port      TEXT NOT NULL,
			rule_idx  INTEGER NOT NULL,
			disabled_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (port, rule_idx)
		)`)
	if err != nil {
		return nil, err
	}

	m := &Monitor{
		db:         db,
		linkReader: linkReader,
		toggler:    toggler,
		stopCh:     make(chan struct{}),
	}
	go m.loop()
	return m, nil
}

// Stop halts the monitor.
func (m *Monitor) Stop() { close(m.stopCh) }

// ── CRUD ──────────────────────────────────────────────────────────────────────

func (m *Monitor) Create(port string, autoDisable bool) error {
	if port == "" {
		return errors.New("port is required")
	}
	ad := 0
	if autoDisable {
		ad = 1
	}
	_, err := m.db.Exec(`INSERT OR IGNORE INTO health_checks (port, auto_disable) VALUES (?,?)`, port, ad)
	return err
}

func (m *Monitor) List() ([]PortCheck, error) {
	rows, err := m.db.Query(`SELECT id, port, enabled, auto_disable, last_status, COALESCE(last_check,'') FROM health_checks ORDER BY port`)
	if err != nil {
		return nil, err
	}
	var out []PortCheck
	for rows.Next() {
		var c PortCheck
		var en, ad int
		if err := rows.Scan(&c.ID, &c.Port, &en, &ad, &c.Status, &c.LastCheck); err != nil {
			rows.Close()
			return nil, err
		}
		c.Enabled = en == 1
		c.AutoDisable = ad == 1
		out = append(out, c)
	}
	scanErr := rows.Err()
	// Close the outer Rows (releasing its DB connection) BEFORE the per-port
	// COUNT queries. Running a nested query inside the rows.Next() loop
	// deadlocks the connection pool: the open Rows holds the only connection
	// while the nested query waits for one that never frees. This locked up
	// every DB user — login included — on the production box.
	rows.Close()
	if scanErr != nil {
		return nil, scanErr
	}
	for i := range out {
		m.db.QueryRow(`SELECT COUNT(*) FROM auto_disabled_rules WHERE port=?`, out[i].Port).Scan(&out[i].AffectedRules)
	}
	return out, nil
}

func (m *Monitor) Delete(id int64) error {
	_, err := m.db.Exec(`DELETE FROM health_checks WHERE id=?`, id)
	return err
}

func (m *Monitor) Toggle(id int64) error {
	_, err := m.db.Exec(`UPDATE health_checks SET enabled=CASE WHEN enabled=1 THEN 0 ELSE 1 END WHERE id=?`, id)
	return err
}

// ── Monitor loop ──────────────────────────────────────────────────────────────

func (m *Monitor) loop() {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			m.check()
		case <-m.stopCh:
			return
		}
	}
}

func (m *Monitor) check() {
	if m.linkReader == nil {
		return
	}
	linkStates := m.linkReader()

	m.mu.Lock()
	defer m.mu.Unlock()

	checks, _ := m.List()
	for _, c := range checks {
		if !c.Enabled {
			continue
		}

		state, ok := linkStates[c.Port]
		if !ok {
			state = "unknown"
		}

		prevStatus := c.Status
		m.db.Exec(`UPDATE health_checks SET last_status=?, last_check=CURRENT_TIMESTAMP WHERE id=?`, state, c.ID)

		if !c.AutoDisable || m.toggler == nil {
			continue
		}

		if state == "down" && prevStatus != "down" {
			// Port went down → disable rules forwarding to it
			if m.toggler != nil {
				m.toggler.DisableByOutput(c.Port)
			}
		} else if state == "up" && prevStatus == "down" {
			// Port recovered → re-enable rules
			if m.toggler != nil {
				m.toggler.EnableByOutput(c.Port)
			}
		}
	}
}
