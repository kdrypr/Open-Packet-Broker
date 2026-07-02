// Package snmpagent provides a lightweight SNMPv2c agent for monitoring
// integration with Zabbix, Nagios, PRTG, LibreNMS etc.
//
// Listens on UDP :161 and responds to GET/GETNEXT requests.
// Exposes system info, interface stats, and broker status via standard
// and enterprise MIBs.
//
// OID tree:
//
//	1.3.6.1.2.1.1.1.0    sysDescr    "Packet Broker vX.X"
//	1.3.6.1.2.1.1.3.0    sysUpTime   timeticks
//	1.3.6.1.2.1.1.5.0    sysName     hostname
//	1.3.6.1.4.1.99999.1  brokerStatus  1=running, 0=stopped
//	1.3.6.1.4.1.99999.2  ruleCount     integer
//	1.3.6.1.4.1.99999.3  cpuPercent    integer
//	1.3.6.1.4.1.99999.4  memPercent    integer
//	1.3.6.1.4.1.99999.5  alertCount    integer
package snmpagent

import (
	"database/sql"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// ── Config ────────────────────────────────────────────────────────────────────

// Config holds SNMP agent settings.
type Config struct {
	ID        int64  `json:"id"`
	Enabled   bool   `json:"enabled"`
	Community string `json:"community"` // SNMPv2c community string
	Port      int    `json:"port"`      // listen port (default 161)
	Location  string `json:"location"`  // sysLocation
	Contact   string `json:"contact"`   // sysContact
	Created   string `json:"created"`
}

// DataProvider supplies live data for SNMP responses.
type DataProvider struct {
	GetBrokerStatus func() string // "running" or "stopped"
	GetRuleCount    func() int
	GetCPUPercent   func() float64
	GetMemPercent   func() float64
	GetAlertCount   func() int
	GetUptime       func() time.Duration
}

// ── Store ─────────────────────────────────────────────────────────────────────

// Store manages SNMP config and runs the agent.
type Store struct {
	db       *sql.DB
	mu       sync.RWMutex
	config   Config
	provider *DataProvider
	stopCh   chan struct{}
	running  bool
}

// New creates the SNMP agent store and runs migrations.
func New(db *sql.DB, provider *DataProvider) (*Store, error) {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS snmp_config (
			id        INTEGER PRIMARY KEY CHECK (id = 1),
			enabled   INTEGER NOT NULL DEFAULT 0,
			community TEXT NOT NULL DEFAULT 'public',
			port      INTEGER NOT NULL DEFAULT 161,
			location  TEXT NOT NULL DEFAULT '',
			contact   TEXT NOT NULL DEFAULT '',
			created   DATETIME DEFAULT CURRENT_TIMESTAMP
		)`)
	if err != nil {
		return nil, err
	}
	_, _ = db.Exec(`INSERT OR IGNORE INTO snmp_config (id) VALUES (1)`)

	s := &Store{
		db:       db,
		provider: provider,
		stopCh:   make(chan struct{}),
	}
	s.load()
	if s.config.Enabled {
		go s.start()
	}
	return s, nil
}

func (s *Store) load() {
	var c Config
	var en int
	s.db.QueryRow(`SELECT id, enabled, community, port, location, contact, created FROM snmp_config WHERE id=1`).
		Scan(&c.ID, &en, &c.Community, &c.Port, &c.Location, &c.Contact, &c.Created)
	c.Enabled = en == 1
	s.mu.Lock()
	s.config = c
	s.mu.Unlock()
}

// GetConfig returns the current SNMP config.
func (s *Store) GetConfig() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

// MaskedSecret is shown in the UI in place of the real community string;
// submitting it back unchanged preserves the stored value.
const MaskedSecret = "********"

// GetConfigMasked is GetConfig with the community string masked, for display
// in the admin UI. The SNMPv2c community acts as a password, so it should
// not be echoed back in cleartext.
func (s *Store) GetConfigMasked() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := s.config
	if c.Community != "" {
		c.Community = MaskedSecret
	}
	return c
}

// SaveConfig updates SNMP settings and restarts agent if needed.
func (s *Store) SaveConfig(enabled bool, community string, port int, location, contact string) error {
	if community == MaskedSecret || community == "" {
		// Operator left the masked value untouched — keep the stored secret.
		s.mu.RLock()
		community = s.config.Community
		s.mu.RUnlock()
	}
	if community == "" {
		community = "public"
	}
	if port <= 0 || port > 65535 {
		port = 161
	}
	en := 0
	if enabled {
		en = 1
	}
	_, err := s.db.Exec(`UPDATE snmp_config SET enabled=?, community=?, port=?, location=?, contact=? WHERE id=1`,
		en, community, port, location, contact)
	if err != nil {
		return err
	}
	s.Stop()
	s.load()
	if s.config.Enabled {
		go s.start()
	}
	return nil
}

// Stop halts the SNMP agent.
func (s *Store) Stop() {
	s.mu.Lock()
	if s.running {
		close(s.stopCh)
		s.stopCh = make(chan struct{})
		s.running = false
	}
	s.mu.Unlock()
}

// ── SNMP Agent (simplified SNMPv2c responder) ─────────────────────────────────

func (s *Store) start() {
	s.mu.Lock()
	s.running = true
	stopCh := s.stopCh
	cfg := s.config
	s.mu.Unlock()

	addr := fmt.Sprintf(":%d", cfg.Port)
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return
	}

	go func() {
		<-stopCh
		conn.Close()
	}()

	buf := make([]byte, 4096)
	for {
		n, remote, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		response := s.handleSNMP(buf[:n], cfg)
		if response != nil {
			conn.WriteTo(response, remote)
		}
	}
}

// buildMIB snapshots the scalar OID tree from the live data provider + config.
func (s *Store) buildMIB(cfg Config) []varbind {
	hostname, _ := os.Hostname()
	status, rules, cpu, mem, alerts, ticks := 0, 0, 0, 0, 0, 0
	if p := s.provider; p != nil {
		if p.GetBrokerStatus != nil && p.GetBrokerStatus() == "running" {
			status = 1
		}
		if p.GetRuleCount != nil {
			rules = p.GetRuleCount()
		}
		if p.GetCPUPercent != nil {
			cpu = int(p.GetCPUPercent())
		}
		if p.GetMemPercent != nil {
			mem = int(p.GetMemPercent())
		}
		if p.GetAlertCount != nil {
			alerts = p.GetAlertCount()
		}
		if p.GetUptime != nil {
			ticks = int(p.GetUptime().Milliseconds() / 10) // TimeTicks = 1/100s
		}
	}
	mib := []varbind{
		vbStr("1.3.6.1.2.1.1.1.0", "Packet Broker on "+hostname),
		vbInt("1.3.6.1.2.1.1.3.0", tagTimeTicks, ticks),
		vbStr("1.3.6.1.2.1.1.4.0", cfg.Contact),
		vbStr("1.3.6.1.2.1.1.5.0", hostname),
		vbStr("1.3.6.1.2.1.1.6.0", cfg.Location),
		vbInt("1.3.6.1.4.1.99999.1.0", tagInteger, status),
		vbInt("1.3.6.1.4.1.99999.2.0", tagGauge32, rules),
		vbInt("1.3.6.1.4.1.99999.3.0", tagGauge32, cpu),
		vbInt("1.3.6.1.4.1.99999.4.0", tagGauge32, mem),
		vbInt("1.3.6.1.4.1.99999.5.0", tagGauge32, alerts),
	}
	sortMIB(mib)
	return mib
}

// handleSNMP parses an SNMPv2c GET/GETNEXT request and returns an encoded
// GET-RESPONSE. Validates the community string; unknown OIDs answer noSuchInstance.
func (s *Store) handleSNMP(pkt []byte, cfg Config) []byte {
	tag, msg, _, ok := tlv(pkt)
	if !ok || tag != tagSequence {
		return nil
	}
	// version INTEGER
	_, _, rest, ok := tlv(msg)
	if !ok {
		return nil
	}
	// community OCTET STRING
	ct, community, rest, ok := tlv(rest)
	if !ok || ct != tagOctetStr || string(community) != cfg.Community {
		return nil
	}
	// PDU
	pduTag, pdu, _, ok := tlv(rest)
	if !ok || (pduTag != tagGetReq && pduTag != tagGetNext) {
		return nil
	}
	// request-id, error-status, error-index, varbind-list
	rt, reqID, pdu2, ok := tlv(pdu)
	if !ok || rt != tagInteger {
		return nil
	}
	_, _, pdu3, ok := tlv(pdu2) // error-status
	if !ok {
		return nil
	}
	_, _, pdu4, ok := tlv(pdu3) // error-index
	if !ok {
		return nil
	}
	vbTag, vbList, _, ok := tlv(pdu4) // varbind list SEQUENCE
	if !ok || vbTag != tagSequence {
		return nil
	}

	mib := s.buildMIB(cfg)
	get := func(oid string) varbind {
		if pduTag == tagGetNext {
			for _, m := range mib { // mib is sorted
				if oidLess(oid, m.oid) {
					return m
				}
			}
			return varbind{oid, enc(tagEndOfMibView, nil)}
		}
		for _, m := range mib {
			if m.oid == oid {
				return m
			}
		}
		return varbind{oid, enc(tagNoSuchInstance, nil)}
	}

	var respVarbinds []byte
	cur := vbList
	for len(cur) > 0 {
		seqTag, vb, next, ok := tlv(cur)
		if !ok {
			break
		}
		cur = next
		if seqTag != tagSequence {
			continue
		}
		ot, oidBytes, _, ok := tlv(vb)
		if !ok || ot != tagOID {
			continue
		}
		r := get(parseOID(oidBytes))
		entry := append(enc(tagOID, encodeOID(r.oid)), r.value...)
		respVarbinds = append(respVarbinds, enc(tagSequence, entry)...)
	}

	// GET-RESPONSE PDU: same request-id, error-status=0, error-index=0, varbinds.
	respPDU := append([]byte{}, enc(tagInteger, reqID)...)
	respPDU = append(respPDU, encInt(tagInteger, 0)...)
	respPDU = append(respPDU, encInt(tagInteger, 0)...)
	respPDU = append(respPDU, enc(tagSequence, respVarbinds)...)

	body := append([]byte{}, encInt(tagInteger, 1)...) // version v2c
	body = append(body, enc(tagOctetStr, community)...)
	body = append(body, enc(tagGetResp, respPDU)...)
	return enc(tagSequence, body)
}

// IsRunning returns whether the SNMP agent is currently active.
func (s *Store) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}
