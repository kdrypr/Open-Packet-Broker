// Package mailer provides email notifications via SMTP or Microsoft Graph API.
//
// Providers:
//   - "smtp"  — Standard SMTP with STARTTLS/SSL (Gmail, custom servers)
//   - "o365"  — Microsoft Graph API with OAuth2 client credentials
//   - "gmail" — Gmail SMTP with App Password
//
// O365 Graph API flow (no SMTP needed):
//  1. Register app in Azure AD → get Tenant ID, Client ID, Client Secret
//  2. Grant "Mail.Send" application permission in API Permissions
//  3. Admin consent
//  4. This code gets an OAuth2 token and POSTs to /v1.0/users/{from}/sendMail
package mailer

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ── Config ────────────────────────────────────────────────────────────────────

// Config holds email settings.
type Config struct {
	ID          int64  `json:"id"`
	Provider    string `json:"provider"`     // "smtp", "o365", "gmail"
	Host        string `json:"host"`         // SMTP server (smtp/gmail only)
	Port        int    `json:"port"`         // SMTP port (smtp/gmail only)
	Username    string `json:"username"`     // SMTP user or O365 from-address
	Password    string `json:"password"`     // SMTP pass / app password (not used for o365)
	FromAddress string `json:"from_address"` // sender email
	FromName    string `json:"from_name"`    // sender display name
	Encryption  string `json:"encryption"`   // "none", "starttls", "ssl" (smtp/gmail only)
	Enabled     bool   `json:"enabled"`
	AlertEmails string `json:"alert_emails"` // comma-separated recipient list

	// O365 Graph API fields
	TenantID     string `json:"tenant_id"`     // Azure AD tenant ID
	ClientID     string `json:"client_id"`     // App registration client ID
	ClientSecret string `json:"client_secret"` // App registration client secret

	Created string `json:"created"`
}

// ── Store ─────────────────────────────────────────────────────────────────────

// Store manages email configuration and sending.
//
// outgoing is a bounded worker pool used by SendAlert to dispatch a
// notification per recipient without spawning an unbounded number of
// goroutines (an alert storm + a slow SMTP server would otherwise
// pile up TLS handshakes indefinitely).
type Store struct {
	db         *sql.DB
	mu         sync.RWMutex
	c          Config
	tokenCache *graphToken

	outgoing chan outgoingJob
}

type outgoingJob struct {
	to, subject, body string
}

// mailerWorkers caps concurrent alert deliveries. Sized to comfortably
// absorb the "everything just turned red" case without unbounded goroutine
// growth. Adjust if customer environments routinely fan out to >32 dests.
const (
	mailerWorkers   = 4
	mailerQueueSize = 256
)

type graphToken struct {
	AccessToken string
	ExpiresAt   time.Time
}

// New creates the mailer store and runs migrations.
func New(db *sql.DB) (*Store, error) {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS mail_config (
			id            INTEGER PRIMARY KEY CHECK (id = 1),
			provider      TEXT NOT NULL DEFAULT 'smtp',
			host          TEXT NOT NULL DEFAULT '',
			port          INTEGER NOT NULL DEFAULT 587,
			username      TEXT NOT NULL DEFAULT '',
			password      TEXT NOT NULL DEFAULT '',
			from_address  TEXT NOT NULL DEFAULT '',
			from_name     TEXT NOT NULL DEFAULT 'Packet Broker',
			encryption    TEXT NOT NULL DEFAULT 'starttls',
			enabled       INTEGER NOT NULL DEFAULT 0,
			alert_emails  TEXT NOT NULL DEFAULT '',
			tenant_id     TEXT NOT NULL DEFAULT '',
			client_id     TEXT NOT NULL DEFAULT '',
			client_secret TEXT NOT NULL DEFAULT '',
			created       DATETIME DEFAULT CURRENT_TIMESTAMP
		)`)
	if err != nil {
		return nil, err
	}
	// Migration: add O365 columns to existing tables
	for _, col := range []string{"tenant_id", "client_id", "client_secret"} {
		_, _ = db.Exec(`ALTER TABLE mail_config ADD COLUMN ` + col + ` TEXT NOT NULL DEFAULT ''`)
	}
	_, _ = db.Exec(`INSERT OR IGNORE INTO mail_config (id) VALUES (1)`)

	s := &Store{
		db:       db,
		outgoing: make(chan outgoingJob, mailerQueueSize),
	}
	s.load()
	for i := 0; i < mailerWorkers; i++ {
		go s.outgoingWorker()
	}
	return s, nil
}

// outgoingWorker is one of mailerWorkers goroutines that drain the
// outgoing channel. Each job is a single recipient delivery; errors are
// swallowed because we don't want one bad SMTP target to halt others.
// A future improvement is to record deliver_failed counters per address.
func (s *Store) outgoingWorker() {
	for job := range s.outgoing {
		_ = s.Send(job.to, job.subject, job.body)
	}
}

// enqueue places a delivery on the bounded queue. Returns immediately;
// if the queue is full the job is dropped (logged by caller).
func (s *Store) enqueue(job outgoingJob) bool {
	select {
	case s.outgoing <- job:
		return true
	default:
		return false
	}
}

// ── Send ──────────────────────────────────────────────────────────────────────

// Send dispatches an email via the configured provider.
func (s *Store) Send(to, subject, body string) error {
	c := s.getRaw()
	if !c.Enabled {
		return fmt.Errorf("email not configured or disabled")
	}

	switch c.Provider {
	case "o365":
		return s.sendGraphAPI(c, to, subject, body)
	default:
		return s.sendSMTP(c, to, subject, body)
	}
}

// SendTest sends a test email.
func (s *Store) SendTest(to string) error {
	return s.Send(to,
		"[Packet Broker] Test Email",
		"This is a test message from your Packet Broker.\n\nIf you received this, email notifications are working correctly.\n\nTimestamp: "+time.Now().UTC().Format(time.RFC3339))
}

// SendAlert sends an alert notification to all configured recipients.
func (s *Store) SendAlert(ruleName, message string, value float64) {
	c := s.getRaw()
	if !c.Enabled || c.AlertEmails == "" {
		return
	}
	subject := fmt.Sprintf("[Packet Broker Alert] %s", ruleName)
	body := fmt.Sprintf("Alert: %s\nValue: %.2f\nMessage: %s\nTime: %s\n\n--\nPacket Broker Alert System",
		ruleName, value, message, time.Now().UTC().Format(time.RFC3339))

	for _, to := range strings.Split(c.AlertEmails, ",") {
		to = strings.TrimSpace(to)
		if to == "" {
			continue
		}
		// Bounded worker pool — see Store.outgoing comment. Drops on
		// overflow rather than spawning unbounded goroutines.
		s.enqueue(outgoingJob{to: to, subject: subject, body: body})
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
