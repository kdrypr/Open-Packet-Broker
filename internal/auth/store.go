package auth

import (
	"database/sql"
	"errors"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// ── User management ───────────────────────────────────────────────────────────

// UserCount returns the number of rows in the users table.
func (s *Store) UserCount() (int, error) {
	var n int
	err := s.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&n)
	return n, err
}

// CreateUser inserts a new user with a bcrypt-hashed password and given role.
// role must be "admin" or "user"; anything else is coerced to "user".
func (s *Store) CreateUser(username, password, role string) error {
	return s.CreateUserForced(username, password, role, false)
}

// CreateUserForced is CreateUser with control over the must-change-password
// bit. The bootstrap admin (admin/admin) is created with mustChange=true so
// the operator is forced through /profile/password on first login. Reused
// by admin "add user" flow with mustChange=true when the admin sets the
// initial password on behalf of someone else.
func (s *Store) CreateUserForced(username, password, role string, mustChange bool) error {
	if role != RoleAdmin && role != RoleUser {
		role = RoleUser
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return err
	}
	must := 0
	if mustChange {
		must = 1
	}
	_, err = s.db.Exec(
		"INSERT INTO users (username, password, role, must_change_password) VALUES (?, ?, ?, ?)",
		username, string(hash), role, must,
	)
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return ErrDuplicateUser
	}
	return err
}

// MustChangePassword reports whether the given user has their forced-
// password-change flag set. Used by middleware to gate access until the
// user updates their password.
func (s *Store) MustChangePassword(userID int64) bool {
	var n int
	_ = s.db.QueryRow("SELECT must_change_password FROM users WHERE id=?", userID).Scan(&n)
	return n != 0
}

// MustChangePasswordByUsername is the username-keyed variant used during
// the request lifecycle when only the username is at hand.
func (s *Store) MustChangePasswordByUsername(username string) bool {
	var n int
	_ = s.db.QueryRow("SELECT must_change_password FROM users WHERE username=?", username).Scan(&n)
	return n != 0
}

// ChangePassword updates the password for the given username, clears
// the must-change-password flag, and invalidates every active session
// for the user (so a parallel attacker session is kicked out).
func (s *Store) ChangePassword(username, newPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcryptCost)
	if err != nil {
		return err
	}
	// Look up the ID first so we can invalidate sessions afterward.
	var id int64
	if err := s.db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&id); err != nil {
		return ErrUserNotFound
	}
	res, err := s.db.Exec(
		"UPDATE users SET password = ?, must_change_password = 0 WHERE id = ?",
		string(hash), id,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrUserNotFound
	}
	s.InvalidateUserSessions(id)
	return nil
}

// ChangePasswordByID updates the password for the given user ID and
// clears the must-change-password flag. Also invalidates every active
// session for that user (admin-forced reset kicks the target user out).
func (s *Store) ChangePasswordByID(id int64, newPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcryptCost)
	if err != nil {
		return err
	}
	res, err := s.db.Exec(
		"UPDATE users SET password = ?, must_change_password = 0 WHERE id = ?",
		string(hash), id,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrUserNotFound
	}
	s.InvalidateUserSessions(id)
	return nil
}

// ListUsers returns all users ordered by creation time.
func (s *Store) ListUsers() ([]UserInfo, error) {
	rows, err := s.db.Query(
		"SELECT id, username, role, created FROM users ORDER BY id",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []UserInfo
	for rows.Next() {
		var u UserInfo
		var created sql.NullString
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &created); err != nil {
			return nil, err
		}
		if created.Valid {
			u.Created = created.String
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// DeleteUser removes a user by ID. Returns an error if it would delete the
// last admin account.
func (s *Store) DeleteUser(id int64) error {
	var role string
	err := s.db.QueryRow("SELECT role FROM users WHERE id = ?", id).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUserNotFound
	}
	if err != nil {
		return err
	}

	if role == RoleAdmin {
		var adminCount int
		if err := s.db.QueryRow("SELECT COUNT(*) FROM users WHERE role='admin'").Scan(&adminCount); err != nil {
			return err
		}
		if adminCount <= 1 {
			return errors.New("cannot delete the last admin account")
		}
	}

	_, err = s.db.Exec("DELETE FROM users WHERE id = ?", id)
	return err
}
