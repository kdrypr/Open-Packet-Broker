package server

import (
	"fmt"
	"os"
	"path/filepath"

	"packet_broker/internal/auth"
)

// SetAdminPassword creates-or-updates the "admin" web UI account with the given
// password (no forced change — the operator chose it deliberately at install).
// Used by appliance provisioning: `packet_broker_ui -set-admin-password`.
func SetAdminPassword(rootDir, password string) error {
	if rootDir == "" {
		rootDir, _ = os.Getwd()
	}
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	st, err := auth.New(filepath.Join(rootDir, "users.db"))
	if err != nil {
		return err
	}
	n, _ := st.UserCount()
	if n == 0 {
		return st.CreateUser("admin", password, auth.RoleAdmin)
	}
	return st.ChangePassword("admin", password)
}
