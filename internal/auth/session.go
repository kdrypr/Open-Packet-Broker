package auth

import (
	"crypto/subtle"
	"net/http"
	"time"
)

// ── Types ─────────────────────────────────────────────────────────────────────

type session struct {
	user         User
	expires      time.Time
	lastActivity time.Time // updated on every request
	csrfToken    string    // one random token per session for CSRF protection
}

// pendingLogin is the short-lived state created between successful
// password validation and TOTP code entry. It is NOT a session — it
// has no CSRF token, can't access any handler, and expires fast.
type pendingLogin struct {
	user    User
	expires time.Time
}

// ── Session management ────────────────────────────────────────────────────────

// InvalidateUserSessions kills every active session belonging to the
// given user ID. Called after a password change so an attacker who
// previously stole a cookie loses access immediately. Also revokes any
// outstanding pending-login states for the same user.
func (s *Store) InvalidateUserSessions(userID int64) int {
	n := 0
	s.mu.Lock()
	for tok, sess := range s.sessions {
		if sess.user.ID == userID {
			delete(s.sessions, tok)
			n++
		}
	}
	for tok, p := range s.pendings {
		if p.user.ID == userID {
			delete(s.pendings, tok)
		}
	}
	s.mu.Unlock()
	return n
}

// Login validates credentials (with rate limiting), creates a session and
// writes the cookie.
// LoginPassword performs the password half of the login flow only. On
// success the user is returned but no session cookie is set yet — the
// handler decides whether to mint a real session (no 2FA) or stash a
// pending-login state and ask for a TOTP code first. Rate limit is
// enforced here so credential stuffing can't bypass it by jumping
// straight to MintSession.
func (s *Store) LoginPassword(r *http.Request, username, password string) (User, error) {
	ip := clientIP(r)
	if !s.limiter.allow(ip) {
		return User{}, ErrRateLimited
	}
	return s.Authenticate(username, password)
}

// MintSession creates the actual session + CSRF token + cookie. Caller
// is responsible for asserting the user has cleared all login factors
// (password and TOTP if enabled).
func (s *Store) MintSession(w http.ResponseWriter, user User) error {
	token, err := randomToken()
	if err != nil {
		return err
	}
	csrf, err := randomToken()
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.sessions[token] = session{
		user:         user,
		expires:      time.Now().Add(SessionExpiry),
		lastActivity: time.Now(),
		csrfToken:    csrf,
	}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(SessionExpiry.Seconds()),
	})
	return nil
}

// BeginPendingLogin stashes the user in a short-lived pre-auth slot,
// sets a separate cookie, and returns. The caller redirects to the
// TOTP challenge page; until the user types a valid code and the
// pending state is consumed by FinalizePendingLogin, the pending
// cookie grants NO access (middleware ignores it).
func (s *Store) BeginPendingLogin(w http.ResponseWriter, user User) error {
	token, err := randomToken()
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.pendings[token] = pendingLogin{user: user, expires: time.Now().Add(PendingExpiry)}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     PendingCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(PendingExpiry.Seconds()),
	})
	return nil
}

// PendingUser returns the user associated with the pending-login cookie
// on this request, or (zero, false) if absent / expired.
func (s *Store) PendingUser(r *http.Request) (User, bool) {
	c, err := r.Cookie(PendingCookieName)
	if err != nil {
		return User{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pendings[c.Value]
	if !ok || time.Now().After(p.expires) {
		delete(s.pendings, c.Value)
		return User{}, false
	}
	return p.user, true
}

// FinalizePendingLogin consumes the pending state, mints the real
// session, and clears the pending cookie. Returns ErrPendingExpired if
// the state is gone or stale.
func (s *Store) FinalizePendingLogin(w http.ResponseWriter, r *http.Request) (User, error) {
	c, err := r.Cookie(PendingCookieName)
	if err != nil {
		return User{}, ErrPendingExpired
	}
	s.mu.Lock()
	p, ok := s.pendings[c.Value]
	delete(s.pendings, c.Value)
	s.mu.Unlock()
	if !ok || time.Now().After(p.expires) {
		return User{}, ErrPendingExpired
	}
	// Clear pending cookie before minting the real session.
	http.SetCookie(w, &http.Cookie{
		Name: PendingCookieName, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	if err := s.MintSession(w, p.user); err != nil {
		return User{}, err
	}
	return p.user, nil
}

// AbortPendingLogin clears any stale pending-login cookie (used when
// the user navigates back to /login while a pending state still exists).
func (s *Store) AbortPendingLogin(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(PendingCookieName); err == nil {
		s.mu.Lock()
		delete(s.pendings, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name: PendingCookieName, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

// Logout invalidates the session and clears the cookie.
func (s *Store) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(CookieName); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// SessionUser returns the logged-in user for the current request.
func (s *Store) SessionUser(r *http.Request) (User, bool) {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return User{}, false
	}
	now := time.Now()
	s.mu.Lock()
	sess, ok := s.sessions[c.Value]
	if !ok || now.After(sess.expires) {
		// Absolute expiry
		if ok {
			delete(s.sessions, c.Value)
		}
		s.mu.Unlock()
		return User{}, false
	}
	if now.Sub(sess.lastActivity) > IdleTimeout {
		// Idle timeout — no activity for too long
		delete(s.sessions, c.Value)
		s.mu.Unlock()
		return User{}, false
	}
	// Update last activity (sliding window)
	sess.lastActivity = now
	s.sessions[c.Value] = sess
	s.mu.Unlock()
	return sess.user, true
}

// IsAdmin returns true if the current session belongs to an admin user.
func (s *Store) IsAdmin(r *http.Request) bool {
	u, ok := s.SessionUser(r)
	return ok && u.Role == RoleAdmin
}

// ── CSRF ──────────────────────────────────────────────────────────────────────

// CSRFToken returns the CSRF token for the current session (empty if not
// authenticated). Embed this in every state-changing HTML form.
func (s *Store) CSRFToken(r *http.Request) string {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return ""
	}
	s.mu.RLock()
	sess, ok := s.sessions[c.Value]
	s.mu.RUnlock()
	if !ok {
		return ""
	}
	return sess.csrfToken
}

// ValidateCSRF checks that the "csrf_token" form field matches the session's
// stored token using constant-time comparison to prevent timing attacks.
func (s *Store) ValidateCSRF(r *http.Request) bool {
	formToken := r.FormValue("csrf_token")
	expected := s.CSRFToken(r)
	if formToken == "" || expected == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(formToken), []byte(expected)) == 1
}
