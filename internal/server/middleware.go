package server

import (
	"net/http"
	"strings"
)

// securityHeaders applies OWASP-recommended response headers to every
// served request. Kept at the outermost middleware so headers land on
// errors and redirects too.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// Strip any fingerprinting headers — no Server/version/framework leak.
		h.Del("Server")
		h.Del("X-Powered-By")
		h.Set("Server", "-")
		// OWASP recommended security headers
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-XSS-Protection", "0") // Disabled: modern browsers' built-in XSS filters cause more issues than they solve
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Content-Security-Policy",
			"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'; media-src 'none'; worker-src 'none'")
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
		h.Set("Pragma", "no-cache")
		h.Set("X-Permitted-Cross-Domain-Policies", "none")
		next.ServeHTTP(w, r)
	})
}

// noAuthPaths is the set of routes reachable without a real session
// cookie. /login starts the flow; /login/totp continues it after the
// password phase (browser carries the pending-login cookie, not a
// real session); /api/cluster/heartbeat uses a separate shared-secret
// auth (constant-time compare in cluster.ValidateHeartbeatAuth).
var noAuthPaths = map[string]bool{
	"/login":                 true,
	"/login/totp":            true,
	"/api/cluster/heartbeat": true,
}

// requireAuth gates every non-login path on a valid session cookie.
func (a *App) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Public assets (branding logo) are reachable pre-auth so the login
		// page can render them. The handler only serves whitelisted image
		// types from the branding dir.
		if noAuthPaths[r.URL.Path] || strings.HasPrefix(r.URL.Path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}
		if _, ok := a.authStore.SessionUser(r); !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireCSRF rejects POSTs that lack a valid CSRF token. Pre-auth
// endpoints (/login, /login/totp) are exempt because no session token
// exists yet; /api/cluster/heartbeat carries its own shared-secret auth.
func (a *App) requireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && !noAuthPaths[r.URL.Path] {
			if err := r.ParseForm(); err != nil {
				http.Error(w, "Bad request", http.StatusBadRequest)
				return
			}
			if !a.authStore.ValidateCSRF(r) {
				http.Error(w, "CSRF validation failed", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// adminOnly wraps a handler so non-admin sessions get 403.
func (a *App) adminOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.authStore.IsAdmin(r) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		h(w, r)
	}
}

// pwChangeAllowedPaths is the allow-list of paths a "must change password"
// user can still reach without first updating their credentials.
var pwChangeAllowedPaths = map[string]bool{
	"/profile":          true, // GET — surfaces the change-password form
	"/profile/password": true, // POST — form submit
	"/logout":           true,
	"/set-lang":         true,
}

// requirePasswordCurrent forces any logged-in user whose
// must_change_password flag is set to update their password before they
// can reach any other page. Closes the "default admin/admin survives
// indefinitely" finding (C2). Static assets and the change-password
// form itself are exempt so the user can actually complete the flow.
func (a *App) requirePasswordCurrent(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if pwChangeAllowedPaths[p] ||
			strings.HasPrefix(p, "/static/") ||
			p == "/login" {
			next.ServeHTTP(w, r)
			return
		}
		u, ok := a.authStore.SessionUser(r)
		if !ok {
			next.ServeHTTP(w, r) // requireAuth will redirect to /login
			return
		}
		if a.authStore.MustChangePasswordByUsername(u.Username) {
			http.Redirect(w, r, "/profile?force=1", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}
