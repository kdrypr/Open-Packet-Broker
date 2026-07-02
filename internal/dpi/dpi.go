// Package dpi provides deep packet inspection and L7 protocol detection.
//
// Detects application-layer protocols from packet payload signatures.
// Supports IT protocols (HTTP, DNS, TLS, SSH, SMTP, FTP, MQTT)
// and OT/ICS protocols (Modbus/TCP, DNP3, S7comm, EtherNet/IP, BACnet, OPC-UA).
//
// Used for:
//   - Application-aware routing (send HTTP to web tools, DNS to DNS tools)
//   - OT/ICS traffic classification (for IDS/security monitoring)
//   - Protocol statistics and visibility
package dpi

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync"
)

// ── Protocol IDs ──────────────────────────────────────────────────────────────

const (
	ProtoUnknown = "unknown"
	ProtoHTTP    = "http"
	ProtoHTTPS   = "https"
	ProtoDNS     = "dns"
	ProtoTLS     = "tls"
	ProtoSSH     = "ssh"
	ProtoSMTP    = "smtp"
	ProtoFTP     = "ftp"
	ProtoMQTT    = "mqtt"
	ProtoRDP     = "rdp"
	ProtoSIP     = "sip"
	ProtoNTP     = "ntp"
	ProtoSNMP    = "snmp"
	ProtoLDAP    = "ldap"
	ProtoSMB     = "smb"

	// OT / ICS protocols
	ProtoModbus     = "modbus"
	ProtoDNP3       = "dnp3"
	ProtoS7comm     = "s7comm"
	ProtoEtherNetIP = "enip"
	ProtoBACnet     = "bacnet"
	ProtoOPCUA      = "opcua"
	ProtoCIP        = "cip"
	ProtoIEC104     = "iec104"
	ProtoGoose      = "goose"
	ProtoMMS        = "mms"
	ProtoFINS       = "fins"
	ProtoHartIP     = "hartip"
	ProtoProfiNet   = "profinet"
)

// Protocol holds metadata about a detected protocol.
type Protocol struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"` // "it", "ot", "unknown"
	Description string `json:"description"`
	Risk        string `json:"risk"` // "low", "medium", "high", "critical"
}

// All known protocols with metadata.
var Protocols = map[string]Protocol{
	ProtoHTTP:       {ProtoHTTP, "HTTP", "it", "Hypertext Transfer Protocol", "low"},
	ProtoHTTPS:      {ProtoHTTPS, "HTTPS", "it", "HTTP over TLS", "low"},
	ProtoDNS:        {ProtoDNS, "DNS", "it", "Domain Name System", "low"},
	ProtoTLS:        {ProtoTLS, "TLS", "it", "Transport Layer Security", "low"},
	ProtoSSH:        {ProtoSSH, "SSH", "it", "Secure Shell", "medium"},
	ProtoSMTP:       {ProtoSMTP, "SMTP", "it", "Simple Mail Transfer Protocol", "low"},
	ProtoFTP:        {ProtoFTP, "FTP", "it", "File Transfer Protocol", "medium"},
	ProtoMQTT:       {ProtoMQTT, "MQTT", "it", "Message Queuing Telemetry Transport", "medium"},
	ProtoRDP:        {ProtoRDP, "RDP", "it", "Remote Desktop Protocol", "high"},
	ProtoSIP:        {ProtoSIP, "SIP", "it", "Session Initiation Protocol", "low"},
	ProtoNTP:        {ProtoNTP, "NTP", "it", "Network Time Protocol", "low"},
	ProtoSNMP:       {ProtoSNMP, "SNMP", "it", "Simple Network Management Protocol", "medium"},
	ProtoLDAP:       {ProtoLDAP, "LDAP", "it", "Lightweight Directory Access Protocol", "medium"},
	ProtoSMB:        {ProtoSMB, "SMB", "it", "Server Message Block", "high"},
	ProtoModbus:     {ProtoModbus, "Modbus/TCP", "ot", "Industrial control protocol (SCADA)", "critical"},
	ProtoDNP3:       {ProtoDNP3, "DNP3", "ot", "Distributed Network Protocol", "critical"},
	ProtoS7comm:     {ProtoS7comm, "S7comm", "ot", "Siemens S7 communication", "critical"},
	ProtoEtherNetIP: {ProtoEtherNetIP, "EtherNet/IP", "ot", "Industrial Ethernet (Rockwell/Allen-Bradley)", "critical"},
	ProtoBACnet:     {ProtoBACnet, "BACnet", "ot", "Building Automation and Control", "high"},
	ProtoOPCUA:      {ProtoOPCUA, "OPC-UA", "ot", "OPC Unified Architecture", "high"},
	ProtoCIP:        {ProtoCIP, "CIP", "ot", "Common Industrial Protocol", "critical"},
	ProtoIEC104:     {ProtoIEC104, "IEC 60870-5-104", "ot", "Telecontrol (power grid SCADA)", "critical"},
	ProtoGoose:      {ProtoGoose, "GOOSE", "ot", "IEC 61850 Generic Object Oriented Substation Event", "critical"},
	ProtoMMS:        {ProtoMMS, "MMS", "ot", "Manufacturing Message Specification (IEC 61850)", "critical"},
	ProtoFINS:       {ProtoFINS, "FINS", "ot", "Omron Factory Intelligent Network Service", "critical"},
	ProtoHartIP:     {ProtoHartIP, "HART-IP", "ot", "Highway Addressable Remote Transducer over IP", "critical"},
	ProtoProfiNet:   {ProtoProfiNet, "PROFINET", "ot", "Siemens PROFINET", "critical"},
}

// ── DPI Rule ──────────────────────────────────────────────────────────────────

// Rule defines a protocol-based routing rule.
type Rule struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Protocol   string `json:"protocol"`    // protocol ID to match
	Category   string `json:"category"`    // "it", "ot", "any"
	Action     string `json:"action"`      // "forward", "mirror", "drop", "alert"
	OutputPort string `json:"output_port"` // destination interface
	Enabled    bool   `json:"enabled"`
	Created    string `json:"created"`
}

// DetectionStat holds per-protocol packet counts.
type DetectionStat struct {
	Protocol string `json:"protocol"`
	Name     string `json:"name"`
	Category string `json:"category"`
	Count    uint64 `json:"count"`
	Bytes    uint64 `json:"bytes"`
	Risk     string `json:"risk"`
}

// ── Store ─────────────────────────────────────────────────────────────────────

// Store manages DPI rules and protocol statistics.
type Store struct {
	db    *sql.DB
	mu    sync.RWMutex
	stats map[string]*DetectionStat // live counters
}

// New creates the DPI store and runs migrations.
func New(db *sql.DB) (*Store, error) {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS dpi_rules (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			name        TEXT NOT NULL,
			protocol    TEXT NOT NULL,
			category    TEXT NOT NULL DEFAULT 'any',
			action      TEXT NOT NULL DEFAULT 'forward',
			output_port TEXT NOT NULL DEFAULT '',
			enabled     INTEGER NOT NULL DEFAULT 1,
			created     DATETIME DEFAULT CURRENT_TIMESTAMP
		)`)
	if err != nil {
		return nil, err
	}
	return &Store{
		db:    db,
		stats: make(map[string]*DetectionStat),
	}, nil
}

// ── Rule CRUD ─────────────────────────────────────────────────────────────────

func (s *Store) CreateRule(name, protocol, category, action, outputPort string) error {
	if name == "" || protocol == "" {
		return fmt.Errorf("name and protocol required")
	}
	en := 1
	_, err := s.db.Exec(`INSERT INTO dpi_rules (name, protocol, category, action, output_port, enabled) VALUES (?,?,?,?,?,?)`,
		name, protocol, category, action, outputPort, en)
	return err
}

func (s *Store) ListRules() ([]Rule, error) {
	rows, err := s.db.Query(`SELECT id, name, protocol, category, action, output_port, enabled, created FROM dpi_rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		var r Rule
		var en int
		if err := rows.Scan(&r.ID, &r.Name, &r.Protocol, &r.Category, &r.Action, &r.OutputPort, &en, &r.Created); err != nil {
			return nil, err
		}
		r.Enabled = en == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) DeleteRule(id int64) error {
	_, err := s.db.Exec(`DELETE FROM dpi_rules WHERE id=?`, id)
	return err
}

func (s *Store) ToggleRule(id int64) error {
	_, err := s.db.Exec(`UPDATE dpi_rules SET enabled=CASE WHEN enabled=1 THEN 0 ELSE 1 END WHERE id=?`, id)
	return err
}

// ── Protocol detection (called from API with packet metadata) ─────────────────

// RecordDetection updates live protocol statistics.
func (s *Store) RecordDetection(protoID string, pktBytes uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.stats[protoID]
	if !ok {
		p := Protocols[protoID]
		st = &DetectionStat{Protocol: protoID, Name: p.Name, Category: p.Category, Risk: p.Risk}
		s.stats[protoID] = st
	}
	st.Count++
	st.Bytes += pktBytes
}

// GetStats returns current detection statistics.
func (s *Store) GetStats() []DetectionStat {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]DetectionStat, 0, len(s.stats))
	for _, st := range s.stats {
		out = append(out, *st)
	}
	return out
}

// ResetStats clears all counters.
func (s *Store) ResetStats() {
	s.mu.Lock()
	s.stats = make(map[string]*DetectionStat)
	s.mu.Unlock()
}

// IsKnownProtocol reports whether id is a protocol the detector can emit.
// A DPI rule for an unknown protocol could never match, so the handler
// rejects it rather than writing dead config to the data plane.
func IsKnownProtocol(id string) bool {
	_, ok := Protocols[id]
	return ok
}

// ListProtocols returns all known protocols grouped by category.
func ListProtocols() []Protocol {
	out := make([]Protocol, 0, len(Protocols))
	for _, p := range Protocols {
		out = append(out, p)
	}
	return out
}

// ── Generate DPI config for C binary ──────────────────────────────────────────

// WriteDPIConf writes dpi.conf for the C binary engine.
// Format: protocol_id,action,output_port per line.
func (s *Store) WriteDPIConf(path string) error {
	rules, _ := s.ListRules()
	var lines []string
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		lines = append(lines, r.Protocol+","+r.Action+","+r.OutputPort)
	}
	content := strings.Join(lines, "\n")
	if content != "" {
		content += "\n"
	}
	return os.WriteFile(path, []byte(content), 0600)
}
