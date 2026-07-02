// Package syslog provides RFC 5424 syslog forwarding to SIEM systems.
//
// Supports UDP and TCP transport. Messages are formatted per RFC 5424:
//
//	<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
//
// Includes a log-file tailer that watches packet_broker.log and forwards
// new entries in real time.
package syslog

import (
	"database/sql"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"packet_broker/internal/safedial"
)

// ── RFC 5424 Facilities ───────────────────────────────────────────────────────

const (
	FacilityLocal0 = 16
	FacilityLocal1 = 17
	FacilityLocal2 = 18
	FacilityLocal3 = 19
	FacilityLocal4 = 20
	FacilityLocal5 = 21
	FacilityLocal6 = 22
	FacilityLocal7 = 23
)

// ── RFC 5424 Severities ───────────────────────────────────────────────────────

const (
	SevEmergency = 0
	SevAlert     = 1
	SevCritical  = 2
	SevError     = 3
	SevWarning   = 4
	SevNotice    = 5
	SevInfo      = 6
	SevDebug     = 7
)

// MapLevelToSeverity converts a log level string to RFC 5424 severity.
func MapLevelToSeverity(level string) int {
	switch strings.ToUpper(level) {
	case "ERROR":
		return SevError
	case "WARN", "WARNING":
		return SevWarning
	case "DEBUG":
		return SevDebug
	case "INFO":
		return SevInfo
	default:
		return SevNotice
	}
}

// ── Config ────────────────────────────────────────────────────────────────────

// Config holds syslog forwarding configuration.
type Config struct {
	ID            int64  `json:"id"`
	Server        string `json:"server"`   // hostname or IP
	Port          int    `json:"port"`     // default 514
	Protocol      string `json:"protocol"` // "udp" or "tcp"
	Facility      int    `json:"facility"` // 16-23 (local0-local7)
	Enabled       bool   `json:"enabled"`
	ForwardAlerts bool   `json:"forward_alerts"` // forward alert events
	ForwardLogs   bool   `json:"forward_logs"`   // forward operational logs
	SourceName    string `json:"source_name"`    // hostname/identifier for SIEM
	Created       string `json:"created"`
}

// ── Store ─────────────────────────────────────────────────────────────────────

// Store manages syslog configuration and provides the send interface.
type Store struct {
	db     *sql.DB
	mu     sync.RWMutex
	config Config
	conn   net.Conn
}

// New creates the syslog store, runs migrations, and loads config.
func New(db *sql.DB) (*Store, error) {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS syslog_config (
			id             INTEGER PRIMARY KEY CHECK (id = 1),
			server         TEXT NOT NULL DEFAULT '',
			port           INTEGER NOT NULL DEFAULT 514,
			protocol       TEXT NOT NULL DEFAULT 'udp',
			facility       INTEGER NOT NULL DEFAULT 16,
			enabled        INTEGER NOT NULL DEFAULT 0,
			forward_alerts INTEGER NOT NULL DEFAULT 1,
			forward_logs   INTEGER NOT NULL DEFAULT 0,
			source_name    TEXT NOT NULL DEFAULT 'Packet Broker',
			created        DATETIME DEFAULT CURRENT_TIMESTAMP
		)`)
	if err != nil {
		return nil, err
	}

	// Ensure row exists
	_, _ = db.Exec(`INSERT OR IGNORE INTO syslog_config (id) VALUES (1)`)
	// Rebrand the stale auto-default (product renamed packet-broker → Packet Broker);
	// only touches the old default, never a deliberately-customised source name.
	_, _ = db.Exec(`UPDATE syslog_config SET source_name='Packet Broker' WHERE source_name='packet-broker'`)

	s := &Store{db: db}
	s.loadConfig()
	return s, nil
}

// ── Config CRUD ───────────────────────────────────────────────────────────────

func (s *Store) loadConfig() {
	var c Config
	var enabled, fwdAlerts, fwdLogs int
	err := s.db.QueryRow(`
		SELECT id, server, port, protocol, facility, enabled,
		       forward_alerts, forward_logs, source_name, created
		FROM syslog_config WHERE id=1
	`).Scan(&c.ID, &c.Server, &c.Port, &c.Protocol, &c.Facility,
		&enabled, &fwdAlerts, &fwdLogs, &c.SourceName, &c.Created)
	if err != nil {
		return
	}
	c.Enabled = enabled == 1
	c.ForwardAlerts = fwdAlerts == 1
	c.ForwardLogs = fwdLogs == 1

	s.mu.Lock()
	s.config = c
	// Close old connection if server changed
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
	s.mu.Unlock()
}

// GetConfig returns the current configuration.
func (s *Store) GetConfig() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

// SaveConfig updates the syslog configuration.
func (s *Store) SaveConfig(server string, port int, protocol string,
	facility int, enabled, forwardAlerts, forwardLogs bool, sourceName string) error {

	if protocol != "tcp" && protocol != "udp" {
		protocol = "udp"
	}
	if port <= 0 || port > 65535 {
		port = 514
	}
	if facility < 0 || facility > 23 {
		facility = FacilityLocal0
	}
	if sourceName == "" {
		sourceName = "Packet Broker"
	}

	boolToInt := func(b bool) int {
		if b {
			return 1
		}
		return 0
	}

	_, err := s.db.Exec(`
		UPDATE syslog_config SET server=?, port=?, protocol=?, facility=?,
		       enabled=?, forward_alerts=?, forward_logs=?, source_name=?
		WHERE id=1`,
		server, port, protocol, facility,
		boolToInt(enabled), boolToInt(forwardAlerts), boolToInt(forwardLogs), sourceName,
	)
	if err != nil {
		return err
	}
	s.loadConfig()
	return nil
}

// ── Send ──────────────────────────────────────────────────────────────────────

// Send transmits a syslog message if enabled.
func (s *Store) Send(severity int, tag, message string) error {
	s.mu.RLock()
	cfg := s.config
	s.mu.RUnlock()

	if !cfg.Enabled || cfg.Server == "" {
		return nil
	}

	pri := cfg.Facility*8 + severity
	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	hostname := cfg.SourceName
	pid := strconv.Itoa(os.Getpid())

	// RFC 5424 format
	msg := fmt.Sprintf("<%d>1 %s %s %s %s - - %s",
		pri, timestamp, hostname, tag, pid, message)

	return s.send(cfg, msg)
}

// CEF (Common Event Format) identity. SIEMs (FortiSIEM, QRadar, Splunk, ArcSight)
// auto-recognise "CEF:0|…" and map vendor/product/fields — so events parse as Packet Broker
// instead of "Unknown_EventType".
const (
	cefVendor  = "Packet Broker"
	cefProduct = "Packet Broker"
	cefVersion = "1.0"
	syslogTag  = "packet-broker" // RFC5424 APP-NAME on every message
)

// cefPunct normalizes Unicode punctuation that LOOKS like ASCII (em/en dashes,
// smart quotes) to its ASCII form. Such characters in a CEF Name are a classic
// break for strict SIEM CEF parsers (FortiSIEM, ArcSight) — they expect ASCII in
// the header fields. Real i18n LETTERS are left intact (the extension/raw payload
// can carry them); only the deceptive look-alike punctuation is folded.
var cefPunct = strings.NewReplacer(
	"—", "-", "–", "-", "‒", "-", "―", "-", // — – ‒ ―
	"‘", "'", "’", "'", // ‘ ’
	"“", `"`, "”", `"`, // “ ”
	"…", "...", // …
	" ", " ", // non-breaking space
)

// cefHdr escapes a CEF header field (pipe + backslash) and ASCII-folds deceptive
// Unicode punctuation so the event parses cleanly on the SIEM.
func cefHdr(s string) string {
	s = cefPunct.Replace(s)
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, "|", `\|`)
}

// cefExt escapes a CEF extension value (equals, backslash, newlines).
func cefExt(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "=", `\=`)
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.ReplaceAll(s, "\r", " ")
}

// cef builds a CEF message: CEF:0|vendor|product|version|sigID|name|sev|ext
func cef(sigID, name string, sev int, ext string) string {
	return fmt.Sprintf("CEF:0|%s|%s|%s|%s|%s|%d|%s", cefVendor, cefProduct, cefVersion, cefHdr(sigID), cefHdr(name), sev, ext)
}

// cefSeverity maps a syslog severity (0-7, lower = worse) to CEF severity (0-10).
func cefSeverity(syslogSev int) int {
	switch {
	case syslogSev <= SevError:
		return 9
	case syslogSev == SevWarning:
		return 6
	case syslogSev == SevNotice:
		return 4
	default:
		return 3
	}
}

// SendAlert sends an alert as a CEF event so the SIEM parses it as an Packet Broker alarm.
func (s *Store) SendAlert(ruleName, message string, value float64) {
	s.mu.RLock()
	cfg := s.config
	s.mu.RUnlock()

	if !cfg.Enabled || !cfg.ForwardAlerts {
		return
	}
	ext := fmt.Sprintf("cs1Label=value cs1=%.2f msg=%s", value, cefExt(message))
	s.Send(SevWarning, syslogTag, cef(ruleName, ruleName, cefSeverity(SevWarning), ext))
}

// severityFromName maps an Packet Broker detection severity label to an RFC5424 severity.
func severityFromName(name string) int {
	switch strings.ToLower(name) {
	case "critical":
		return SevCritical
	case "high":
		return SevError
	case "medium":
		return SevWarning
	case "low":
		return SevNotice
	default:
		return SevInfo
	}
}

// SendDetection forwards a detection/alarm to the configured SIEM as a CEF
// event — so broker alarms reach the SIEM and parse as standard CEF events, not
// just broker-internal alerts. Self-gating on Enabled +
// ForwardAlerts, so the ingest path can call it unconditionally (no-op when off).
func (s *Store) SendDetection(engine, rule, severity, srcIP, dstIP, technique, title, user string) {
	s.mu.RLock()
	cfg := s.config
	s.mu.RUnlock()
	if !cfg.Enabled || !cfg.ForwardAlerts {
		return
	}
	sev := severityFromName(severity)
	name := title
	if name == "" {
		name = rule
	}
	if name == "" {
		name = "Packet Broker detection"
	}
	sigID := rule
	if sigID == "" {
		sigID = "pb-detection"
	}
	var ext strings.Builder
	if srcIP != "" {
		fmt.Fprintf(&ext, "src=%s ", srcIP)
	}
	if dstIP != "" {
		fmt.Fprintf(&ext, "dst=%s ", dstIP)
	}
	if user != "" {
		fmt.Fprintf(&ext, "suser=%s ", cefExt(user)) // CEF standard source-user field
	}
	if engine != "" {
		fmt.Fprintf(&ext, "cs1Label=engine cs1=%s ", cefExt(engine))
	}
	if technique != "" {
		fmt.Fprintf(&ext, "cs2Label=technique cs2=%s ", cefExt(technique))
	}
	fmt.Fprintf(&ext, "cs3Label=severity cs3=%s act=detected", cefExt(severity))
	_ = s.Send(sev, syslogTag, cef(sigID, name, cefSeverity(sev), strings.TrimSpace(ext.String())))
}

// SendLog ships a raw log line (log forwarding — not an event, kept human-readable).
func (s *Store) SendLog(level, message string) {
	s.mu.RLock()
	cfg := s.config
	s.mu.RUnlock()

	if !cfg.Enabled || !cfg.ForwardLogs {
		return
	}

	severity := MapLevelToSeverity(level)
	s.Send(severity, syslogTag, message)
}

// SendTest sends a test message using a fresh connection (not cached).
func (s *Store) SendTest() error {
	s.mu.RLock()
	cfg := s.config
	s.mu.RUnlock()

	if cfg.Server == "" {
		return fmt.Errorf("syslog server not configured")
	}

	pri := cfg.Facility*8 + SevInfo
	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	hostname := cfg.SourceName
	pid := strconv.Itoa(os.Getpid())

	body := cef("connectivity-test", "Packet Broker syslog connectivity test", 1, "msg=Packet Broker syslog connectivity verified")
	msg := fmt.Sprintf("<%d>1 %s %s %s %s - - %s",
		pri, timestamp, hostname, syslogTag, pid, body)

	// Use a fresh connection for test to avoid stale cache issues
	addr := net.JoinHostPort(cfg.Server, strconv.Itoa(cfg.Port))
	var conn net.Conn
	var err error
	// Relay-safe dialer: an operator-set syslog target must not reach the
	// appliance's own loopback / cloud-metadata (SSRF port-scan oracle); RFC1918
	// collectors on the management LAN stay reachable.
	dialer := safedial.RelayDialer(5 * time.Second)
	switch cfg.Protocol {
	case "tcp":
		conn, err = dialer.Dial("tcp", addr)
	default:
		conn, err = dialer.Dial("udp", addr)
	}
	if err != nil {
		return fmt.Errorf("syslog connect %s: %w", addr, err)
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	payload := msg
	if cfg.Protocol == "tcp" {
		payload = msg + "\n"
	}
	_, err = conn.Write([]byte(payload))
	if err != nil {
		return fmt.Errorf("syslog write: %w", err)
	}
	return nil
}

func (s *Store) send(cfg Config, msg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	addr := net.JoinHostPort(cfg.Server, strconv.Itoa(cfg.Port))

	if s.conn == nil {
		var err error
		dialer := safedial.RelayDialer(5 * time.Second)
		switch cfg.Protocol {
		case "tcp":
			s.conn, err = dialer.Dial("tcp", addr)
		default:
			s.conn, err = dialer.Dial("udp", addr)
		}
		if err != nil {
			return fmt.Errorf("syslog connect %s: %w", addr, err)
		}
	}

	s.conn.SetWriteDeadline(time.Now().Add(3 * time.Second))

	// TCP syslog uses newline-delimited framing (octet counting is also valid)
	payload := msg
	if cfg.Protocol == "tcp" {
		payload = msg + "\n"
	}

	_, err := s.conn.Write([]byte(payload))
	if err != nil {
		// Connection broken, reset for next attempt
		s.conn.Close()
		s.conn = nil
		return fmt.Errorf("syslog write: %w", err)
	}
	return nil
}

// Close shuts down the syslog connection.
func (s *Store) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
}

// ── Log file tailer ───────────────────────────────────────────────────────────

// StartTailer watches a log file and forwards new lines to syslog.
// It runs in a goroutine. Call the returned stop function to halt it.
func (s *Store) StartTailer(logPath string) (stop func()) {
	stopCh := make(chan struct{})

	go func() {
		var lastSize int64

		// Get initial file size (skip existing content)
		if fi, err := os.Stat(logPath); err == nil {
			lastSize = fi.Size()
		}

		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				s.mu.RLock()
				enabled := s.config.Enabled && s.config.ForwardLogs
				s.mu.RUnlock()
				if !enabled {
					continue
				}

				fi, err := os.Stat(logPath)
				if err != nil || fi.Size() <= lastSize {
					if err == nil && fi.Size() < lastSize {
						lastSize = 0 // file was truncated/rotated
					}
					continue
				}

				f, err := os.Open(logPath)
				if err != nil {
					continue
				}

				f.Seek(lastSize, 0)
				buf := make([]byte, fi.Size()-lastSize)
				// io.ReadFull + advancing by bytes ACTUALLY read: a single
				// os.File.Read may return short, which previously advanced
				// lastSize to the full size and silently dropped the unread tail.
				n, _ := io.ReadFull(f, buf)
				f.Close()
				lastSize += int64(n)

				if n > 0 {
					lines := strings.Split(string(buf[:n]), "\n")
					for _, line := range lines {
						line = strings.TrimSpace(line)
						if line == "" {
							continue
						}
						// Parse level from line
						level := "INFO"
						msg := line
						for _, tag := range []string{"[ERROR]", "[WARN]", "[WARNING]", "[DEBUG]", "[INFO]"} {
							if idx := strings.Index(line, tag); idx != -1 {
								level = strings.Trim(tag, "[]")
								msg = strings.TrimSpace(line[idx+len(tag):])
								break
							}
						}
						s.SendLog(level, msg)
					}
				}
			}
		}
	}()

	return func() { close(stopCh) }
}
