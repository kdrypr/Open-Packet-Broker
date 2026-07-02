// Package alerts provides threshold-based monitoring with webhook notifications.
package alerts

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"packet_broker/internal/safedial"
)

// ── Types ─────────────────────────────────────────────────────────────────────

// Rule defines a threshold alert.
type Rule struct {
	ID            int64   `json:"id"`
	Name          string  `json:"name"`
	Metric        string  `json:"metric"` // "drop_rate", "link_down", "rx_errors", "cpu", "memory"
	Threshold     float64 `json:"threshold"`
	Operator      string  `json:"operator"`  // ">", "<", "="
	Interface     string  `json:"interface"` // optional, "" = all
	WebhookURL    string  `json:"webhook_url"`
	Enabled       bool    `json:"enabled"`
	Created       string  `json:"created"`
	LastTriggered string  `json:"last_triggered"`
}

// Event is a fired alert instance.
type Event struct {
	ID           int64   `json:"id"`
	AlertRuleID  int64   `json:"alert_rule_id"`
	RuleName     string  `json:"rule_name"`
	Value        float64 `json:"value"`
	Message      string  `json:"message"`
	Timestamp    string  `json:"timestamp"`
	Acknowledged bool    `json:"acknowledged"`
}

// MetricReader is a function that returns current metric values.
// Keys depend on metric type: "cpu" → {"cpu": 75.2}, "drop_rate" → {"eth0": 0.05}
type MetricReader func(metric string) map[string]float64

// ── Store ─────────────────────────────────────────────────────────────────────

// SyslogSender is called when an alert fires, to forward to SIEM.
type SyslogSender func(ruleName, message string, value float64)

// Store manages alert rules and events in SQLite.
type Store struct {
	db         *sql.DB
	mu         sync.Mutex
	readMetric MetricReader
	syslog     SyslogSender
	cooldowns  map[int64]time.Time // last trigger time per rule ID
	stopCh     chan struct{}
}

// New creates the alerts store, runs migrations, and starts the evaluator goroutine.
func New(db *sql.DB, reader MetricReader) (*Store, error) {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS alert_rules (
			id             INTEGER PRIMARY KEY AUTOINCREMENT,
			name           TEXT NOT NULL,
			metric         TEXT NOT NULL,
			threshold      REAL NOT NULL,
			operator       TEXT NOT NULL DEFAULT '>',
			interface      TEXT NOT NULL DEFAULT '',
			webhook_url    TEXT NOT NULL DEFAULT '',
			enabled        INTEGER NOT NULL DEFAULT 1,
			created        DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_triggered DATETIME
		)`)
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS alert_events (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			alert_rule_id INTEGER NOT NULL,
			value         REAL NOT NULL,
			message       TEXT NOT NULL,
			timestamp     DATETIME DEFAULT CURRENT_TIMESTAMP,
			acknowledged  INTEGER NOT NULL DEFAULT 0
		)`)
	if err != nil {
		return nil, err
	}

	s := &Store{
		db:         db,
		readMetric: reader,
		cooldowns:  make(map[int64]time.Time),
		stopCh:     make(chan struct{}),
	}
	go s.evaluatorLoop()
	return s, nil
}

// Stop halts the evaluator.
func (s *Store) Stop() { close(s.stopCh) }

// SetSyslog attaches a syslog sender for alert forwarding to SIEM.
func (s *Store) SetSyslog(fn SyslogSender) { s.syslog = fn }

// ── CRUD ──────────────────────────────────────────────────────────────────────

func (s *Store) CreateRule(name, metric, operator, iface, webhookURL string, threshold float64) error {
	_, err := s.db.Exec(
		`INSERT INTO alert_rules (name, metric, threshold, operator, interface, webhook_url) VALUES (?,?,?,?,?,?)`,
		name, metric, threshold, operator, iface, webhookURL,
	)
	return err
}

func (s *Store) ListRules() ([]Rule, error) {
	rows, err := s.db.Query(`SELECT id, name, metric, threshold, operator, interface, webhook_url, enabled, created, COALESCE(last_triggered,'') FROM alert_rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		var r Rule
		var enabled int
		if err := rows.Scan(&r.ID, &r.Name, &r.Metric, &r.Threshold, &r.Operator, &r.Interface, &r.WebhookURL, &enabled, &r.Created, &r.LastTriggered); err != nil {
			return nil, err
		}
		r.Enabled = enabled == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) DeleteRule(id int64) error {
	_, err := s.db.Exec(`DELETE FROM alert_rules WHERE id=?`, id)
	return err
}

func (s *Store) ToggleRule(id int64) error {
	_, err := s.db.Exec(`UPDATE alert_rules SET enabled = CASE WHEN enabled=1 THEN 0 ELSE 1 END WHERE id=?`, id)
	return err
}

func (s *Store) ListEvents(limit int) ([]Event, error) {
	rows, err := s.db.Query(`
		SELECT e.id, e.alert_rule_id, COALESCE(r.name,'(deleted)'), e.value, e.message, e.timestamp, e.acknowledged
		FROM alert_events e LEFT JOIN alert_rules r ON e.alert_rule_id=r.id
		ORDER BY e.id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var ev Event
		var ack int
		if err := rows.Scan(&ev.ID, &ev.AlertRuleID, &ev.RuleName, &ev.Value, &ev.Message, &ev.Timestamp, &ack); err != nil {
			return nil, err
		}
		ev.Acknowledged = ack == 1
		out = append(out, ev)
	}
	return out, rows.Err()
}

func (s *Store) AcknowledgeEvent(id int64) error {
	_, err := s.db.Exec(`UPDATE alert_events SET acknowledged=1 WHERE id=?`, id)
	return err
}

func (s *Store) UnackedCount() int {
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM alert_events WHERE acknowledged=0`).Scan(&n)
	return n
}

// ── Evaluator ─────────────────────────────────────────────────────────────────

const cooldownDuration = 5 * time.Minute

func (s *Store) evaluatorLoop() {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			s.evaluate()
		case <-s.stopCh:
			return
		}
	}
}

func (s *Store) evaluate() {
	if s.readMetric == nil {
		return
	}
	rules, err := s.ListRules()
	if err != nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		// Cooldown check
		if last, ok := s.cooldowns[r.ID]; ok && now.Before(last.Add(cooldownDuration)) {
			continue
		}

		values := s.readMetric(r.Metric)
		for iface, val := range values {
			if r.Interface != "" && r.Interface != iface {
				continue
			}
			triggered := false
			switch r.Operator {
			case ">":
				triggered = val > r.Threshold
			case "<":
				triggered = val < r.Threshold
			case "=":
				triggered = val == r.Threshold
			}
			if !triggered {
				continue
			}

			msg := fmt.Sprintf("[%s] %s on %s: %.2f %s %.2f", r.Name, r.Metric, iface, val, r.Operator, r.Threshold)
			s.db.Exec(`INSERT INTO alert_events (alert_rule_id, value, message) VALUES (?,?,?)`, r.ID, val, msg)
			s.db.Exec(`UPDATE alert_rules SET last_triggered=CURRENT_TIMESTAMP WHERE id=?`, r.ID)
			s.cooldowns[r.ID] = now

			if r.WebhookURL != "" {
				go sendWebhook(r.WebhookURL, msg, r.Name, val)
			}
			if s.syslog != nil {
				go s.syslog(r.Name, msg, val)
			}
			break // one trigger per rule per cycle
		}
	}
}

func sendWebhook(url, message, ruleName string, value float64) {
	payload, _ := json.Marshal(map[string]any{
		"alert":   ruleName,
		"message": message,
		"value":   value,
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
	// safedial.Client refuses connections to private / metadata IPs and
	// disables redirects — defeats SSRF if a (compromised) admin sets
	// the webhook URL to an internal target.
	client := safedial.Client(5 * time.Second)
	resp, err := client.Post(url, "application/json", bytes.NewReader(payload))
	if err == nil {
		// Drain + close so the connection/fd returns to the pool — without this
		// every alert fire leaks an HTTP response body.
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}
