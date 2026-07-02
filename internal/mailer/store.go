package mailer

import (
	"fmt"

	"packet_broker/internal/secretbox"
	"packet_broker/internal/sanitize"
)

// unseal decrypts a stored secret, transparently passing through legacy
// plaintext values (secretbox.Open returns non-magic input unchanged). seal
// encrypts before persistence; both are no-ops when no PB_SECRET_KEY is set.
func unseal(stored string) string {
	if stored == "" {
		return ""
	}
	if pt, err := secretbox.Open([]byte(stored)); err == nil {
		return string(pt)
	}
	return stored
}

func seal(plain string) string {
	if plain == "" {
		return ""
	}
	return string(secretbox.Seal([]byte(plain)))
}

// ── Config persistence ──────────────────────────────────────────────────────────

func (s *Store) load() {
	var c Config
	var enabled int
	err := s.db.QueryRow(`
		SELECT id, provider, host, port, username, password,
		       from_address, from_name, encryption, enabled, alert_emails,
		       tenant_id, client_id, client_secret, created
		FROM mail_config WHERE id=1
	`).Scan(&c.ID, &c.Provider, &c.Host, &c.Port, &c.Username, &c.Password,
		&c.FromAddress, &c.FromName, &c.Encryption, &enabled, &c.AlertEmails,
		&c.TenantID, &c.ClientID, &c.ClientSecret, &c.Created)
	if err != nil {
		return
	}
	c.Enabled = enabled == 1
	// Decrypt secrets at rest (transparent for legacy plaintext rows).
	c.Password = unseal(c.Password)
	c.ClientSecret = unseal(c.ClientSecret)
	s.mu.Lock()
	s.c = c
	s.mu.Unlock()
}

// GetConfig returns current config with secrets masked.
func (s *Store) GetConfig() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := s.c
	if c.Password != "" {
		c.Password = "********"
	}
	if c.ClientSecret != "" {
		c.ClientSecret = "********"
	}
	return c
}

func (s *Store) getRaw() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.c
}

// SaveConfig updates the email configuration.
func (s *Store) SaveConfig(provider, host string, port int, username, password,
	fromAddr, fromName, encryption, alertEmails,
	tenantID, clientID, clientSecret string, enabled bool) error {

	switch provider {
	case "o365":
		// Graph API — no SMTP host needed
	case "gmail":
		if host == "" {
			host = "smtp.gmail.com"
		}
		if port == 0 {
			port = 587
		}
		if encryption == "" {
			encryption = "starttls"
		}
	default:
		provider = "smtp"
	}
	if port <= 0 || port > 65535 {
		port = 587
	}
	if encryption != "starttls" && encryption != "ssl" && encryption != "none" {
		encryption = "starttls"
	}
	if fromName == "" {
		fromName = "Packet Broker"
	}
	// Reject hostnames carrying injection characters before they reach the
	// dialer. (The dialer additionally vetoes loopback/metadata IPs at
	// connect time via safedial.RelayDialer.)
	if provider != "o365" && host != "" {
		if _, err := sanitize.ExternalHost(host); err != nil {
			return fmt.Errorf("SMTP host: %w", err)
		}
	}

	// Keep existing secrets if masked
	s.mu.RLock()
	if password == "********" || password == "" {
		password = s.c.Password
	}
	if clientSecret == "********" || clientSecret == "" {
		clientSecret = s.c.ClientSecret
	}
	s.mu.RUnlock()

	en := 0
	if enabled {
		en = 1
	}
	// Seal secrets before they touch disk (mirrors the connector stores; no-op
	// without PB_SECRET_KEY).
	_, err := s.db.Exec(`
		UPDATE mail_config SET provider=?, host=?, port=?, username=?, password=?,
		       from_address=?, from_name=?, encryption=?, enabled=?, alert_emails=?,
		       tenant_id=?, client_id=?, client_secret=?
		WHERE id=1`,
		provider, host, port, username, seal(password),
		fromAddr, fromName, encryption, en, alertEmails,
		tenantID, clientID, seal(clientSecret),
	)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.tokenCache = nil // invalidate token on config change
	s.mu.Unlock()
	s.load()
	return nil
}
