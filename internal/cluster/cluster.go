// Package cluster manages multi-node broker coordination.
// A broker can be "standalone", "controller", or "node".
package cluster

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"packet_broker/internal/safedial"
)

// ── Types ─────────────────────────────────────────────────────────────────────

// NodeInfo represents a broker node's status.
type NodeInfo struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	Address       string `json:"address"` // e.g. "192.168.1.10:8005"
	Status        string `json:"status"`  // "online", "offline"
	Role          string `json:"role"`    // HA role (computed): "active", "standby", "offline"
	RuleCount     int    `json:"rule_count"`
	BrokerStatus  string `json:"broker_status"` // "running", "stopped"
	Uptime        string `json:"uptime"`
	LastHeartbeat string `json:"last_heartbeat"`
	Registered    string `json:"registered"`
}

// Config holds cluster configuration.
//
// Secret is a 32-byte random token base64-encoded; it authenticates
// /api/cluster/heartbeat requests in both directions:
//
//   - On a controller it's the shared secret nodes must present.
//   - On a node it's the controller secret the node sends with each beat.
//
// Auto-generated the first time controller mode is enabled (and
// regeneratable by the operator). The controller surfaces it in the UI
// so the admin can copy/paste into each node's config.
type Config struct {
	Mode          string `json:"mode"`           // "standalone", "controller", "node"
	ControllerURL string `json:"controller_url"` // URL of controller (for node mode)
	NodeName      string `json:"node_name"`
	NodeAddress   string `json:"node_address"` // this node's reachable address
	Secret        string `json:"secret"`       // base64 shared secret (cluster auth)
	// HA topology (controller computes node roles from this):
	//   active-passive — one node active, the rest warm standby; the controller
	//                    auto-promotes the next online standby if the active drops.
	//   active-active  — every online node serves simultaneously.
	HAMode string `json:"ha_mode"`
}

// Heartbeat is the payload nodes send to the controller.
type Heartbeat struct {
	Name         string `json:"name"`
	Address      string `json:"address"`
	RuleCount    int    `json:"rule_count"`
	BrokerStatus string `json:"broker_status"`
	Uptime       string `json:"uptime"`
}

// ErrBadSecret is returned by ValidateHeartbeatAuth when the request
// does not carry a matching shared secret.
var ErrBadSecret = errors.New("cluster: invalid or missing shared secret")

// HeartbeatHeader is the HTTP header carrying the shared cluster secret.
const HeartbeatHeader = "X-Cluster-Secret"

// ── Manager ───────────────────────────────────────────────────────────────────

// Manager handles cluster operations.
type Manager struct {
	db      *sql.DB
	mu      sync.RWMutex
	config  Config
	stopCh  chan struct{}
	running bool

	// Callbacks for node mode
	getHeartbeat func() Heartbeat
}

// New creates the cluster manager and runs migrations.
func New(db *sql.DB) (*Manager, error) {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS cluster_nodes (
			id             INTEGER PRIMARY KEY AUTOINCREMENT,
			name           TEXT NOT NULL UNIQUE,
			address        TEXT NOT NULL,
			status         TEXT NOT NULL DEFAULT 'online',
			rule_count     INTEGER NOT NULL DEFAULT 0,
			broker_status  TEXT NOT NULL DEFAULT 'stopped',
			uptime         TEXT NOT NULL DEFAULT '',
			last_heartbeat DATETIME DEFAULT CURRENT_TIMESTAMP,
			registered     DATETIME DEFAULT CURRENT_TIMESTAMP
		)`)
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS cluster_config (
			id             INTEGER PRIMARY KEY CHECK (id = 1),
			mode           TEXT NOT NULL DEFAULT 'standalone',
			controller_url TEXT NOT NULL DEFAULT '',
			node_name      TEXT NOT NULL DEFAULT '',
			node_address   TEXT NOT NULL DEFAULT '',
			secret         TEXT NOT NULL DEFAULT ''
		)`)
	if err != nil {
		return nil, err
	}
	// Idempotent column adds — pre-existing DBs may not have these.
	_, _ = db.Exec(`ALTER TABLE cluster_config ADD COLUMN secret TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE cluster_config ADD COLUMN ha_mode TEXT NOT NULL DEFAULT 'active-passive'`)
	_, _ = db.Exec(`INSERT OR IGNORE INTO cluster_config (id) VALUES (1)`)

	m := &Manager{db: db, stopCh: make(chan struct{})}
	m.loadConfig()
	return m, nil
}

func (m *Manager) loadConfig() {
	var c Config
	m.db.QueryRow(`SELECT mode, controller_url, node_name, node_address, secret, ha_mode FROM cluster_config WHERE id=1`).
		Scan(&c.Mode, &c.ControllerURL, &c.NodeName, &c.NodeAddress, &c.Secret, &c.HAMode)
	if c.Mode == "" {
		c.Mode = "standalone"
	}
	if c.HAMode == "" {
		c.HAMode = "active-passive"
	}
	m.mu.Lock()
	m.config = c
	m.mu.Unlock()
}

// GetConfig returns the current cluster config.
func (m *Manager) GetConfig() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}

// genSecret produces a 32-byte random token, base64-url-encoded.
func genSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// SaveConfig updates cluster configuration.
//
// Auto-generates a fresh secret when transitioning into controller mode
// for the first time (existing Secret preserved otherwise). Nodes are
// expected to receive the controller's secret out of band (UI copy).
func (m *Manager) SaveConfig(mode, controllerURL, nodeName, nodeAddress, secret string) error {
	if mode != "controller" && mode != "node" {
		mode = "standalone"
	}

	// If switching to controller and no secret supplied, mint one.
	if mode == "controller" {
		current := m.GetConfig()
		if secret == "" {
			secret = current.Secret
		}
		if secret == "" {
			s, err := genSecret()
			if err != nil {
				return err
			}
			secret = s
		}
	}

	_, err := m.db.Exec(
		`UPDATE cluster_config SET mode=?, controller_url=?, node_name=?, node_address=?, secret=? WHERE id=1`,
		mode, controllerURL, nodeName, nodeAddress, secret)
	if err != nil {
		return err
	}
	m.loadConfig()
	return nil
}

// RegenerateSecret replaces the cluster secret with a fresh random
// 32-byte token. Nodes must be re-provisioned with the new value.
func (m *Manager) RegenerateSecret() (string, error) {
	s, err := genSecret()
	if err != nil {
		return "", err
	}
	if _, err := m.db.Exec(`UPDATE cluster_config SET secret=? WHERE id=1`, s); err != nil {
		return "", err
	}
	m.loadConfig()
	return s, nil
}

// SetHAMode updates the HA topology mode (active-passive | active-active).
func (m *Manager) SetHAMode(haMode string) error {
	if haMode != "active-active" {
		haMode = "active-passive"
	}
	if _, err := m.db.Exec(`UPDATE cluster_config SET ha_mode=? WHERE id=1`, haMode); err != nil {
		return err
	}
	m.loadConfig()
	return nil
}

// ValidateHeartbeatAuth checks the inbound heartbeat carries a matching
// shared secret in HeartbeatHeader. Constant-time compare prevents
// timing oracles. Returns nil on match.
func (m *Manager) ValidateHeartbeatAuth(r *http.Request) error {
	cfg := m.GetConfig()
	if cfg.Mode != "controller" {
		return ErrBadSecret // accept heartbeats only on controllers
	}
	want := []byte(cfg.Secret)
	got := []byte(r.Header.Get(HeartbeatHeader))
	if len(want) == 0 {
		// Mis-provisioned controller: refuse rather than accept open.
		return ErrBadSecret
	}
	if subtle.ConstantTimeCompare(want, got) != 1 {
		return ErrBadSecret
	}
	return nil
}

// SetHeartbeatCallback sets the function to get current node status.
func (m *Manager) SetHeartbeatCallback(fn func() Heartbeat) {
	m.getHeartbeat = fn
}

// Start begins background operations based on mode. It is idempotent:
// calling it again (e.g. after a cluster-config save) cleanly stops the
// previous loop before starting the new one, so repeated saves don't leak
// a goroutine per call. The loop is handed its own stopCh so a later
// Start/Stop cycle can never signal the wrong generation.
func (m *Manager) Start() {
	m.Stop() // tear down any previous loop first
	cfg := m.GetConfig()
	m.mu.Lock()
	m.stopCh = make(chan struct{})
	stop := m.stopCh
	switch cfg.Mode {
	case "node":
		m.running = true
		go m.nodeLoop(stop)
	case "controller":
		m.running = true
		go m.controllerLoop(stop)
	}
	m.mu.Unlock()
}

// Stop halts background operations. Safe to call when not running and
// safe to call repeatedly.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.running {
		return
	}
	close(m.stopCh)
	m.running = false
}

// ── Controller operations ─────────────────────────────────────────────────────

// RegisterNode handles a node registration/heartbeat.
func (m *Manager) RegisterNode(hb Heartbeat) error {
	_, err := m.db.Exec(`
		INSERT INTO cluster_nodes (name, address, rule_count, broker_status, uptime, last_heartbeat)
		VALUES (?,?,?,?,?,CURRENT_TIMESTAMP)
		ON CONFLICT(name) DO UPDATE SET
			address=?, rule_count=?, broker_status=?, uptime=?, status='online', last_heartbeat=CURRENT_TIMESTAMP`,
		hb.Name, hb.Address, hb.RuleCount, hb.BrokerStatus, hb.Uptime,
		hb.Address, hb.RuleCount, hb.BrokerStatus, hb.Uptime)
	return err
}

// ListNodes returns all registered nodes with their computed HA role. Online is
// derived live from heartbeat freshness (<35s); roles follow the HA mode:
//   - active-active: every online node is "active".
//   - active-passive: the first online node (by registration order) is "active",
//     the rest are "standby". If the active drops offline, the next online node
//     becomes active automatically — that is the failover.
func (m *Manager) ListNodes() ([]NodeInfo, error) {
	rows, err := m.db.Query(`
		SELECT id, name, address, rule_count, broker_status, uptime, last_heartbeat, registered,
		       CASE WHEN (julianday('now') - julianday(last_heartbeat)) * 86400 < 35 THEN 1 ELSE 0 END AS online
		FROM cluster_nodes ORDER BY registered, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NodeInfo
	haMode := m.GetConfig().HAMode
	activeAssigned := false
	for rows.Next() {
		var n NodeInfo
		var online int
		if err := rows.Scan(&n.ID, &n.Name, &n.Address, &n.RuleCount, &n.BrokerStatus, &n.Uptime, &n.LastHeartbeat, &n.Registered, &online); err != nil {
			return nil, err
		}
		if online == 0 {
			n.Status, n.Role = "offline", "offline"
		} else {
			n.Status = "online"
			if haMode == "active-active" {
				n.Role = "active"
			} else if !activeAssigned {
				n.Role = "active" // first online node = primary (or promoted standby on failover)
				activeAssigned = true
			} else {
				n.Role = "standby"
			}
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (m *Manager) controllerLoop(stop <-chan struct{}) {
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			// Mark nodes as offline if no heartbeat for 30s
			m.db.Exec(`UPDATE cluster_nodes SET status='offline' WHERE last_heartbeat < datetime('now', '-30 seconds')`)
		case <-stop:
			return
		}
	}
}

// ── Node operations ───────────────────────────────────────────────────────────

func (m *Manager) nodeLoop(stop <-chan struct{}) {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			m.sendHeartbeat()
		case <-stop:
			return
		}
	}
}

func (m *Manager) sendHeartbeat() {
	cfg := m.GetConfig()
	if cfg.ControllerURL == "" || m.getHeartbeat == nil {
		return
	}
	hb := m.getHeartbeat()
	hb.Name = cfg.NodeName
	hb.Address = cfg.NodeAddress
	data, _ := json.Marshal(hb)

	req, err := http.NewRequest(http.MethodPost,
		cfg.ControllerURL+"/api/cluster/heartbeat", bytes.NewReader(data))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeartbeatHeader, cfg.Secret)
	// safedial.Client refuses to connect to private / link-local /
	// metadata-service IPs and disables redirects — defeats SSRF if an
	// admin (or compromise) sets ControllerURL to an internal target.
	resp, err := safedial.Client(5 * time.Second).Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}
