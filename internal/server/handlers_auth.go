package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"packet_broker/internal/auth"
	"packet_broker/internal/errx"
)

// ---------------------------------------------------------------------------
// Auth handlers
// ---------------------------------------------------------------------------

func (a *App) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.authStore.SessionUser(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	name, logo := a.loginBranding()
	data := LoginData{
		Error:        r.URL.Query().Get("error"),
		DefaultAdmin: a.defaultAdminActive(),
		ProductName:  name,
		LogoURL:      logo,
	}
	a.loginTmpl.ExecuteTemplate(w, "login.html", data)
}

func (a *App) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	user, err := a.authStore.LoginPassword(r, username, password)
	if err != nil {
		a.info("Failed login for: " + sanitizeLogField(username))
		msg := "Invalid username or password"
		if err == auth.ErrRateLimited {
			msg = "Too many login attempts. Please wait a minute."
		}
		errx.RedirectErrorMsg(w, r, "/login", msg)
		return
	}

	// 2FA enforcement: if TOTP is enabled for this user, password alone
	// is NOT sufficient. Stash a short-lived pending state and redirect
	// the user to the TOTP challenge. The real session cookie is only
	// minted by handleLoginTOTPSubmit after the code validates.
	if a.totpStore != nil && a.totpStore.IsEnabled(user.ID) {
		if err := a.authStore.BeginPendingLogin(w, user); err != nil {
			a.logErr("BeginPendingLogin: " + err.Error())
			errx.RedirectErrorMsg(w, r, "/login", "Login failed, please try again")
			return
		}
		http.Redirect(w, r, "/login/totp", http.StatusSeeOther)
		return
	}

	// No 2FA — straight to session.
	if err := a.authStore.MintSession(w, user); err != nil {
		a.logErr("MintSession: " + err.Error())
		errx.RedirectErrorMsg(w, r, "/login", "Login failed, please try again")
		return
	}
	a.info("User logged in: " + sanitizeLogField(username))
	a.auditStore.Log(username, "login", "User logged in", r.RemoteAddr)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// handleLoginTOTPPage renders the 2FA challenge form. Only reachable
// when a valid pending-login cookie is present (otherwise → /login).
func (a *App) handleLoginTOTPPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.authStore.PendingUser(r); !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	name, logo := a.loginBranding()
	data := LoginData{
		Error:       r.URL.Query().Get("error"),
		TOTPMode:    true,
		ProductName: name,
		LogoURL:     logo,
	}
	if err := a.loginTmpl.ExecuteTemplate(w, "login.html", data); err != nil {
		a.logErr("Render login (totp): " + err.Error())
	}
}

// handleLoginTOTPSubmit verifies the TOTP code and, on success,
// finalizes the pending login (mints real session, clears pending).
func (a *App) handleLoginTOTPSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	user, ok := a.authStore.PendingUser(r)
	if !ok {
		errx.RedirectErrorMsg(w, r, "/login", "Session expired, please log in again")
		return
	}
	code := strings.TrimSpace(r.FormValue("totp"))
	if code == "" || !a.totpStore.Verify(user.ID, code) {
		a.info("Failed TOTP for: " + sanitizeLogField(user.Username))
		errx.RedirectErrorMsg(w, r, "/login/totp", "Invalid 2FA code")
		return
	}
	if _, err := a.authStore.FinalizePendingLogin(w, r); err != nil {
		errx.RedirectError(w, r, "/login", err)
		return
	}
	a.info("User logged in (2FA): " + sanitizeLogField(user.Username))
	a.auditStore.Log(user.Username, "login_2fa", "User logged in (2FA verified)", r.RemoteAddr)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// sanitizeLogField strips CR/LF (and clamps length) from a user-
// supplied string before it appears in a log line — closes the log
// injection / SIEM dashboard poisoning class.
func sanitizeLogField(s string) string {
	r := strings.NewReplacer("\r", " ", "\n", " ", "\t", " ")
	out := r.Replace(s)
	if len(out) > 256 {
		out = out[:256]
	}
	return out
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	u, _ := a.authStore.SessionUser(r)
	a.authStore.Logout(w, r)
	if u.Username != "" {
		a.info("User logged out: " + u.Username)
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---------------------------------------------------------------------------
// Profile
// ---------------------------------------------------------------------------

func (a *App) handleProfile(w http.ResponseWriter, r *http.Request) {
	u, _ := a.authStore.SessionUser(r)
	data := a.baseData(r, "profile")
	data.FlashError = r.URL.Query().Get("error")
	data.FlashSuccess = r.URL.Query().Get("success")
	data.TOTPEnabled = a.totpStore.IsEnabled(u.ID)
	if !data.TOTPEnabled {
		secret, uri, _ := a.totpStore.GenerateSecret(u.ID, u.Username)
		data.TOTPSecret = secret
		data.TOTPURI = uri
	}
	a.render(w, "profile.html", data)
}

func (a *App) handleProfilePassword(w http.ResponseWriter, r *http.Request) {
	u, ok := a.authStore.SessionUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	current := r.FormValue("current_password")
	newPw := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")

	fail := func(msg string) {
		errx.RedirectErrorMsg(w, r, "/profile", msg)
	}
	if newPw != confirm {
		fail("Passwords do not match")
		return
	}
	if len(newPw) < 8 {
		fail("Password must be at least 8 characters")
		return
	}
	if _, err := a.authStore.Authenticate(u.Username, current); err != nil {
		fail("Current password is incorrect")
		return
	}
	if err := a.authStore.ChangePassword(u.Username, newPw); err != nil {
		a.logErr("ChangePassword: " + err.Error())
		fail("Failed to change password")
		return
	}
	a.info("Password changed for: " + u.Username)
	a.authStore.Logout(w, r)
	errx.RedirectErrorMsg(w, r, "/login", "Password changed. Please sign in again.")
}

// ---------------------------------------------------------------------------
// Admin — user management
// ---------------------------------------------------------------------------

func (a *App) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	userList, _ := a.authStore.ListUsers()
	data := a.baseData(r, "users")
	data.Users = userList
	data.FlashError = r.URL.Query().Get("error")
	data.FlashSuccess = r.URL.Query().Get("success")
	a.render(w, "users.html", data)
}

func (a *App) handleAdminAddUser(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	role := r.FormValue("role")
	fail := func(msg string) {
		errx.RedirectErrorMsg(w, r, "/admin/users", msg)
	}
	if username == "" {
		fail("Username is required")
		return
	}
	if len(password) < 8 {
		fail("Password must be at least 8 characters")
		return
	}
	if role != auth.RoleAdmin && role != auth.RoleUser {
		role = auth.RoleUser
	}
	// Admin-created accounts must change their password on first login
	// — the admin shouldn't continue to know the user's credentials.
	if err := a.authStore.CreateUserForced(username, password, role, true); err != nil {
		if errors.Is(err, auth.ErrDuplicateUser) {
			fail("Username already exists")
		} else {
			fail("Failed to create user")
		}
		return
	}
	a.info("Admin created user: " + username + " (role=" + role + ")")
	errx.RedirectSuccess(w, r, "/admin/users", "User "+username+" created")
}

func (a *App) handleAdminUserPassword(w http.ResponseWriter, r *http.Request) {
	id, ok := errx.ParseID(r, "id")
	if !ok {
		errx.BadRequest(w, "invalid id")
		return
	}
	newPw := r.FormValue("new_password")
	fail := func(msg string) {
		errx.RedirectErrorMsg(w, r, "/admin/users", msg)
	}
	if len(newPw) < 8 {
		fail("Password must be at least 8 characters")
		return
	}
	if err := a.authStore.ChangePasswordByID(id, newPw); err != nil {
		fail("Failed to change password")
		return
	}
	a.info("Admin changed password for user ID " + strconv.FormatInt(id, 10))
	errx.RedirectSuccess(w, r, "/admin/users", "Password updated")
}

func (a *App) handleAdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := errx.ParseID(r, "id")
	if !ok {
		errx.BadRequest(w, "invalid id")
		return
	}
	me, _ := a.authStore.SessionUser(r)
	if me.ID == id {
		errx.RedirectErrorMsg(w, r, "/admin/users", "You cannot delete your own account")
		return
	}
	if err := a.authStore.DeleteUser(id); err != nil {
		errx.RedirectError(w, r, "/admin/users", err)
		return
	}
	a.info("Admin deleted user ID " + strconv.FormatInt(id, 10))
	errx.RedirectSuccess(w, r, "/admin/users", "User deleted")
}
