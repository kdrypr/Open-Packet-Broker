// Package totp implements RFC 6238 TOTP (Time-based One-Time Password)
// for two-factor authentication with Google Authenticator / Authy.
//
// Pure Go, no external dependencies. Uses HMAC-SHA1 with 6-digit codes.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"
)

const (
	digits    = 6
	period    = 30 // seconds
	skew      = 1  // allow ±1 time step
	issuer    = "PacketBroker"
	secretLen = 20 // 160-bit secret
)

// ── Store ─────────────────────────────────────────────────────────────────────

// Store manages TOTP secrets in SQLite (one per user).
type Store struct{ db *sql.DB }

// New creates the TOTP store and runs migrations.
func New(db *sql.DB) (*Store, error) {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS totp_secrets (
		user_id   INTEGER PRIMARY KEY,
		secret    TEXT NOT NULL,
		enabled   INTEGER NOT NULL DEFAULT 0,
		last_step INTEGER NOT NULL DEFAULT 0,
		created   DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		return nil, err
	}
	// Add the replay-protection column to databases created before it
	// existed. Errors ("duplicate column") are expected and ignored.
	db.Exec(`ALTER TABLE totp_secrets ADD COLUMN last_step INTEGER NOT NULL DEFAULT 0`)
	return &Store{db: db}, nil
}

// GenerateSecret creates a new random TOTP secret for a user.
// Returns the base32-encoded secret and the otpauth:// URI for QR codes.
func (s *Store) GenerateSecret(userID int64, username string) (secret, uri string, err error) {
	b := make([]byte, secretLen)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	secret = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)

	// Store (not yet enabled until user verifies)
	_, err = s.db.Exec(`INSERT INTO totp_secrets (user_id, secret, enabled) VALUES (?,?,0)
		ON CONFLICT(user_id) DO UPDATE SET secret=?, enabled=0`, userID, secret, secret)
	if err != nil {
		return "", "", err
	}

	uri = fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=%d&period=%d",
		issuer, username, secret, issuer, digits, period)
	return secret, uri, nil
}

// Verify checks a TOTP code. If valid and 2FA is not yet enabled, enables it.
// Each time-step can be consumed at most once: a code that has already been
// used (or any code from an earlier-or-equal step) is rejected, defeating
// replay of a sniffed/phished code within its ±skew validity window.
func (s *Store) Verify(userID int64, code string) bool {
	var secret string
	var lastStep int64
	err := s.db.QueryRow(`SELECT secret, last_step FROM totp_secrets WHERE user_id=?`, userID).
		Scan(&secret, &lastStep)
	if err != nil {
		return false
	}

	step, ok := matchCode(secret, code)
	if !ok {
		return false
	}
	// Reject a step already consumed (or older than the last one used).
	if step <= lastStep {
		return false
	}
	// Atomically claim the step. If a concurrent request already advanced
	// last_step to >= step, RowsAffected is 0 and we reject the replay.
	// The same statement enables 2FA on the first successful verification.
	res, err := s.db.Exec(
		`UPDATE totp_secrets SET last_step=?, enabled=1 WHERE user_id=? AND last_step<?`,
		step, userID, step)
	if err != nil {
		return false
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false
	}
	return true
}

// IsEnabled returns true if user has 2FA enabled and verified.
func (s *Store) IsEnabled(userID int64) bool {
	var enabled int
	err := s.db.QueryRow(`SELECT enabled FROM totp_secrets WHERE user_id=? AND enabled=1`, userID).Scan(&enabled)
	return err == nil && enabled == 1
}

// Disable removes 2FA for a user.
func (s *Store) Disable(userID int64) error {
	_, err := s.db.Exec(`DELETE FROM totp_secrets WHERE user_id=?`, userID)
	return err
}

// GetSecret returns the secret for QR display (only if not yet enabled).
func (s *Store) GetSecret(userID int64) (secret string, enabled bool) {
	var en int
	err := s.db.QueryRow(`SELECT secret, enabled FROM totp_secrets WHERE user_id=?`, userID).Scan(&secret, &en)
	if err != nil {
		return "", false
	}
	return secret, en == 1
}

// ── TOTP Algorithm (RFC 6238) ─────────────────────────────────────────────────

// matchCode returns the time-step the code is valid for (within ±skew) and
// whether it matched. The comparison is constant-time to avoid leaking code
// digits through timing.
func matchCode(secret, code string) (int64, bool) {
	now := time.Now().Unix()
	for i := -skew; i <= skew; i++ {
		t := (now / period) + int64(i)
		if subtle.ConstantTimeCompare([]byte(generateCode(secret, t)), []byte(code)) == 1 {
			return t, true
		}
	}
	return 0, false
}

func generateCode(secret string, counter int64) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return ""
	}

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(counter))

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	hash := mac.Sum(nil)

	offset := hash[len(hash)-1] & 0xf
	code := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff
	code = code % uint32(math.Pow10(digits))

	return fmt.Sprintf("%0*d", digits, code)
}
