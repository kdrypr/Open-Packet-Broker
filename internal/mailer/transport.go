package mailer

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/smtp"
	"net/url"
	"time"

	"packet_broker/internal/safedial"
)

// ══════════════════════════════════════════════════════════════════════════════
// ── Microsoft Graph API (O365) ────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

// Graph API sendMail: POST https://graph.microsoft.com/v1.0/users/{from}/sendMail
// Auth: OAuth2 client_credentials → Bearer token
// Permissions: Mail.Send (Application)

func (s *Store) sendGraphAPI(c Config, to, subject, body string) error {
	if c.TenantID == "" || c.ClientID == "" || c.ClientSecret == "" {
		return fmt.Errorf("O365: tenant_id, client_id, and client_secret are required")
	}
	from := c.FromAddress
	if from == "" {
		from = c.Username
	}
	if from == "" {
		return fmt.Errorf("O365: from_address is required")
	}

	token, err := s.getGraphToken(c)
	if err != nil {
		return fmt.Errorf("O365 token: %w", err)
	}

	// Build Graph API request body
	payload := map[string]any{
		"message": map[string]any{
			"subject": subject,
			"body": map[string]string{
				"contentType": "Text",
				"content":     body,
			},
			"from": map[string]any{
				"emailAddress": map[string]string{
					"address": from,
					"name":    c.FromName,
				},
			},
			"toRecipients": []map[string]any{
				{
					"emailAddress": map[string]string{
						"address": to,
					},
				},
			},
		},
		"saveToSentItems": "false",
	}

	jsonBody, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	graphURL := fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s/sendMail", url.PathEscape(from))

	req, err := http.NewRequest("POST", graphURL, bytes.NewReader(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := safedial.Client(15 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("O365 API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 202 || resp.StatusCode == 200 {
		return nil // success
	}

	respBody, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("O365 API %d: %s", resp.StatusCode, truncate(string(respBody), 300))
}

// getGraphToken obtains an OAuth2 access token using client_credentials grant.
// Caches the token until expiry.
func (s *Store) getGraphToken(c Config) (string, error) {
	s.mu.RLock()
	if s.tokenCache != nil && time.Now().Before(s.tokenCache.ExpiresAt) {
		t := s.tokenCache.AccessToken
		s.mu.RUnlock()
		return t, nil
	}
	s.mu.RUnlock()

	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", url.PathEscape(c.TenantID))

	data := url.Values{
		"client_id":     {c.ClientID},
		"client_secret": {c.ClientSecret},
		"scope":         {"https://graph.microsoft.com/.default"},
		"grant_type":    {"client_credentials"},
	}

	client := safedial.Client(10 * time.Second)
	resp, err := client.PostForm(tokenURL, data)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("token parse: %w", err)
	}
	if result.Error != "" {
		return "", fmt.Errorf("O365 auth: %s — %s", result.Error, result.ErrorDesc)
	}
	if result.AccessToken == "" {
		return "", fmt.Errorf("O365: empty access token")
	}

	// Cache token (expire 5 min early to be safe)
	s.mu.Lock()
	s.tokenCache = &graphToken{
		AccessToken: result.AccessToken,
		ExpiresAt:   time.Now().Add(time.Duration(result.ExpiresIn-300) * time.Second),
	}
	s.mu.Unlock()

	return result.AccessToken, nil
}

// ══════════════════════════════════════════════════════════════════════════════
// ── SMTP ──────────────────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

func (s *Store) sendSMTP(c Config, to, subject, body string) error {
	if c.Host == "" {
		return fmt.Errorf("SMTP host not configured")
	}
	from := c.FromAddress
	if from == "" {
		from = c.Username
	}

	msg := fmt.Sprintf("From: %s <%s>\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nDate: %s\r\n\r\n%s",
		c.FromName, from, to, subject,
		time.Now().UTC().Format(time.RFC1123Z), body)

	addr := fmt.Sprintf("%s:%d", c.Host, c.Port)
	auth := smtp.PlainAuth("", c.Username, c.Password, c.Host)

	switch c.Encryption {
	case "ssl":
		return s.sendSSL(addr, auth, from, to, []byte(msg), c)
	case "starttls":
		return s.sendSTARTTLS(addr, auth, from, to, []byte(msg), c)
	default:
		return s.sendPlain(addr, auth, from, to, []byte(msg), c)
	}
}

// sendPlain dials over a relay-safe dialer (rejects loopback/metadata/
// multicast targets, see safedial.RelayDialer) instead of smtp.SendMail,
// which would dial any host the config points at — an SSRF + cleartext
// credential-leak primitive when encryption=none.
func (s *Store) sendPlain(addr string, auth smtp.Auth, from, to string, msg []byte, c Config) error {
	conn, err := safedial.RelayDialer(10*time.Second).Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("connect %s: %w", addr, err)
	}
	client, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer client.Close()
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("auth: %w", err)
	}
	return deliver(client, from, to, msg)
}

func (s *Store) sendSTARTTLS(addr string, auth smtp.Auth, from, to string, msg []byte, c Config) error {
	conn, err := safedial.RelayDialer(10*time.Second).Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("connect %s: %w", addr, err)
	}
	client, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer client.Close()
	if err := client.StartTLS(&tls.Config{ServerName: c.Host}); err != nil {
		return fmt.Errorf("STARTTLS: %w", err)
	}
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("auth: %w", err)
	}
	return deliver(client, from, to, msg)
}

func (s *Store) sendSSL(addr string, auth smtp.Auth, from, to string, msg []byte, c Config) error {
	conn, err := tls.DialWithDialer(safedial.RelayDialer(10*time.Second), "tcp", addr, &tls.Config{ServerName: c.Host})
	if err != nil {
		return fmt.Errorf("TLS connect %s: %w", addr, err)
	}
	client, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer client.Close()
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("auth: %w", err)
	}
	return deliver(client, from, to, msg)
}

// deliver runs the MAIL/RCPT/DATA/QUIT sequence shared by all SMTP paths.
func deliver(client *smtp.Client, from, to string, msg []byte) error {
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("mail from: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("rcpt to: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}
	return client.Quit()
}
