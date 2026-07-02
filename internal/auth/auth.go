// Package auth handles user authentication via SQLite + bcrypt and
// in-memory session management using secure random tokens.
//
// Designed for embedded single-node deployments: no external dependencies
// beyond modernc.org/sqlite (pure-Go, no CGO required).
package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// ── Constants ────────────────────────────────────────────────────────────────

const (
	CookieName        = "pb_session"
	PendingCookieName = "pb_pending"
	PendingExpiry     = 5 * time.Minute
	SessionExpiry     = 8 * time.Hour    // max session lifetime
	IdleTimeout       = 30 * time.Minute // kick after 30min inactivity
	bcryptCost        = 12

	// Rate limiter: max attempts per window per IP.
	maxLoginAttempts = 5
	rateLimitWindow  = time.Minute

	RoleAdmin = "admin"
	RoleUser  = "user"
)

// ErrInvalidCredentials is returned when username/password don't match.
var ErrInvalidCredentials = errors.New("invalid username or password")

// ErrRateLimited is returned when an IP exceeds the login attempt limit.
var ErrRateLimited = errors.New("too many login attempts, please wait a minute")

// ErrPendingExpired is returned when a TOTP challenge is submitted with
// no matching (or stale) pending-login state — e.g. the user took
// longer than PendingExpiry to enter the code, or hit /login/totp
// directly without first submitting credentials.
var ErrPendingExpired = errors.New("login session expired — please re-enter your password")

// ErrUserNotFound / ErrDuplicateUser are sentinel errors callers can match
// with errors.Is, instead of string-matching driver error text (fragile —
// "UNIQUE constraint failed" is a modernc/sqlite implementation detail).
var (
	ErrUserNotFound  = errors.New("user not found")
	ErrDuplicateUser = errors.New("username already exists")
)

// dummyHash is pre-computed once at startup. It is used in Authenticate()
// when a user does not exist, so that the bcrypt work always runs and
// timing-based username enumeration is prevented.
var dummyHash []byte

func init() {
	h, err := bcrypt.GenerateFromPassword([]byte("pb_dummy_placeholder_do_not_use"), bcryptCost)
	if err != nil {
		panic("auth: failed to generate dummy hash: " + err.Error())
	}
	dummyHash = h
}

// ── Types ─────────────────────────────────────────────────────────────────────

// User is the authenticated identity stored in a session.
type User struct {
	ID       int64
	Username string
	Role     string // "admin" | "user"
}

// UserInfo is the view of a user returned when listing (admin UI).
type UserInfo struct {
	ID       int64
	Username string
	Role     string
	Created  string
}

// rateEntry tracks login attempts for a single IP.
type rateEntry struct {
	mu        sync.Mutex
	count     int
	windowEnd time.Time
}

// rateLimiter is a simple in-memory IP-keyed sliding window limiter.
type rateLimiter struct {
	mu      sync.Mutex
	entries map[string]*rateEntry
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{entries: make(map[string]*rateEntry)}
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	e, ok := rl.entries[ip]
	if !ok {
		e = &rateEntry{}
		rl.entries[ip] = e
	}
	rl.mu.Unlock()

	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()
	if now.After(e.windowEnd) {
		e.count = 0
		e.windowEnd = now.Add(rateLimitWindow)
	}
	e.count++
	return e.count <= maxLoginAttempts
}

// Store manages users in SQLite and active sessions in memory.
type Store struct {
	db       *sql.DB
	mu       sync.RWMutex
	sessions map[string]session
	pendings map[string]pendingLogin // pre-auth → awaiting TOTP
	limiter  *rateLimiter
}

// ── Constructor ───────────────────────────────────────────────────────────────

// New opens (or creates) the SQLite database at dbPath, runs migrations,
// and returns a ready-to-use Store.
//
// The DSN forces WAL journal mode + a 5s busy_timeout — without these,
// the shared *sql.DB handle (used by ~14 other stores) deadlocks on
// concurrent writes under load.
//
// MaxOpenConns is a small pool (NOT 1). With a single connection, any code
// path that runs a query while an outer Rows is still open self-deadlocks
// forever (the open Rows holds the lone connection; the inner query waits
// for one that never frees). That exact bug locked up the whole UI in
// production. WAL gives lock-free concurrent readers and busy_timeout(5000)
// makes the serialized writers retry instead of erroring, so a small pool is
// both safe and far more robust than pinning to 1.
//
// The file is force-chmod'd to 0600 — it contains bcrypt hashes, TOTP
// secrets and SMTP/O365 credentials; world-readable would be a leak.
func New(dbPath string) (*Store, error) {
	dsn := dbPath + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	if err := db.Ping(); err != nil {
		return nil, err
	}
	// Tighten file permissions in case earlier umask left it world-readable.
	if fi, err := os.Stat(dbPath); err == nil && fi.Mode().Perm() != 0o600 {
		_ = os.Chmod(dbPath, 0o600)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id                    INTEGER PRIMARY KEY AUTOINCREMENT,
			username              TEXT UNIQUE NOT NULL COLLATE NOCASE,
			password              TEXT NOT NULL,
			role                  TEXT NOT NULL DEFAULT 'admin',
			must_change_password  INTEGER NOT NULL DEFAULT 0,
			created               DATETIME DEFAULT CURRENT_TIMESTAMP
		)`)
	if err != nil {
		return nil, err
	}

	// Idempotent migrations for pre-existing databases.
	_, _ = db.Exec(`ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin'`)
	_, _ = db.Exec(`ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0`)

	return &Store{
		db:       db,
		sessions: make(map[string]session),
		pendings: make(map[string]pendingLogin),
		limiter:  newRateLimiter(),
	}, nil
}

// DB returns the underlying *sql.DB handle so other packages can share the
// same SQLite connection (safe for concurrent use).
func (s *Store) DB() *sql.DB { return s.db }

// ── Auth ──────────────────────────────────────────────────────────────────────

// Authenticate validates credentials and returns the User on success.
//
// Timing attack prevention: when the user does not exist we still run bcrypt
// so that both branches take the same wall-clock time.
func (s *Store) Authenticate(username, password string) (User, error) {
	var u User
	var hash string
	err := s.db.QueryRow(
		"SELECT id, username, password, role FROM users WHERE username = ?",
		username,
	).Scan(&u.ID, &u.Username, &hash, &u.Role)

	if errors.Is(err, sql.ErrNoRows) {
		bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return User{}, ErrInvalidCredentials
	}
	if err != nil {
		return User{}, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return User{}, ErrInvalidCredentials
	}
	return u, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// trustedProxies is the parsed list of IPs (or CIDRs) from the
// TRUSTED_PROXIES env var. Only requests arriving from these addresses
// have their X-Forwarded-For / X-Real-IP headers honored; everywhere
// else they're ignored (an attacker can send any header they want, so
// trusting them blindly would let them bypass per-IP rate limits).
//
// Format: comma-separated list, e.g. "10.0.0.1,192.168.1.0/24". Set
// only when the appliance sits behind a reverse proxy you control.
var trustedProxies = parseTrustedProxies(os.Getenv("TRUSTED_PROXIES"))

type trustedProxy struct {
	ip  net.IP // nil if cidr is set
	net *net.IPNet
}

func parseTrustedProxies(s string) []trustedProxy {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []trustedProxy
	for _, raw := range strings.Split(s, ",") {
		t := strings.TrimSpace(raw)
		if t == "" {
			continue
		}
		if _, ipn, err := net.ParseCIDR(t); err == nil {
			out = append(out, trustedProxy{net: ipn})
		} else if ip := net.ParseIP(t); ip != nil {
			out = append(out, trustedProxy{ip: ip})
		}
	}
	return out
}

func remoteAddrIsTrustedProxy(remote string) bool {
	if len(trustedProxies) == 0 {
		return false
	}
	host := remote
	if h, _, err := net.SplitHostPort(remote); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, tp := range trustedProxies {
		if tp.net != nil && tp.net.Contains(ip) {
			return true
		}
		if tp.ip != nil && tp.ip.Equal(ip) {
			return true
		}
	}
	return false
}

// ClientIP is the exported form of clientIP, for callers outside this
// package (e.g. the audit log) that must record the same trusted-proxy-aware
// client address rather than a spoofable raw X-Forwarded-For.
func ClientIP(r *http.Request) string { return clientIP(r) }

// clientIP extracts the real client IP from the request. Honors XFF /
// XRealIP ONLY when the direct peer (r.RemoteAddr) is in the
// TRUSTED_PROXIES allowlist — otherwise the headers are ignored and
// the rate limiter sees the actual TCP peer, closing the XFF-spoof
// rate-limit-bypass class flagged by the audit.
func clientIP(r *http.Request) string {
	if remoteAddrIsTrustedProxy(r.RemoteAddr) {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			return strings.TrimSpace(strings.SplitN(fwd, ",", 2)[0])
		}
		if real := r.Header.Get("X-Real-IP"); real != "" {
			return real
		}
	}
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}
