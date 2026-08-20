package appcfg

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestNormalizeAutoStart(t *testing.T) {
	cases := map[string]string{
		"off":     AutoStartOff,
		"OFF":     AutoStartOff,
		" 0 ":     AutoStartOff,
		"false":   AutoStartOff,
		"restore": AutoStartRestore,
		"last":    AutoStartRestore,
		"always":  AutoStartAlways,
		"1":       AutoStartAlways,
		"yes":     AutoStartAlways,
		"":        "",
		"maybe":   "",
	}
	for in, want := range cases {
		if got := NormalizeAutoStart(in); got != want {
			t.Errorf("NormalizeAutoStart(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAutoStartDefaultsAndPersistence(t *testing.T) {
	db := openDB(t)
	s, err := New(db)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if got := s.Get().AutoStart; got != DefaultAutoStart {
		t.Fatalf("fresh install AutoStart = %q, want %q", got, DefaultAutoStart)
	}
	// A fresh appliance has no operator intent yet, so "restore" must not
	// start a data plane nobody has ever started.
	if got := s.Get().DesiredState; got != StateStopped {
		t.Fatalf("fresh install DesiredState = %q, want %q", got, StateStopped)
	}

	if err := s.SetAutoStart("Always"); err != nil {
		t.Fatalf("SetAutoStart: %v", err)
	}
	if got := s.Get().AutoStart; got != AutoStartAlways {
		t.Fatalf("AutoStart = %q, want %q", got, AutoStartAlways)
	}
	if err := s.SetAutoStart("sometimes"); err == nil {
		t.Fatal("SetAutoStart accepted an unknown mode")
	}
	if got := s.Get().AutoStart; got != AutoStartAlways {
		t.Fatalf("rejected write changed AutoStart to %q", got)
	}

	if err := s.SetDesiredState(StateRunning); err != nil {
		t.Fatalf("SetDesiredState: %v", err)
	}

	// Reopening the store is what a reboot does: both values must survive.
	s2, err := New(db)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got := s2.Get().AutoStart; got != AutoStartAlways {
		t.Errorf("AutoStart after restart = %q, want %q", got, AutoStartAlways)
	}
	if got := s2.Get().DesiredState; got != StateRunning {
		t.Errorf("DesiredState after restart = %q, want %q", got, StateRunning)
	}
}

// TestMigrationFromPreAutoStartSchema covers upgrading an appliance whose
// app_config table predates the auto-start columns.
func TestMigrationFromPreAutoStartSchema(t *testing.T) {
	db := openDB(t)
	if _, err := db.Exec(`
		CREATE TABLE app_config (
			id           INTEGER PRIMARY KEY CHECK (id = 1),
			product_name TEXT NOT NULL DEFAULT '',
			logo_path    TEXT NOT NULL DEFAULT '',
			fqdn         TEXT NOT NULL DEFAULT ''
		)`); err != nil {
		t.Fatalf("legacy schema: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO app_config (id, product_name, fqdn) VALUES (1, 'Acme Broker', 'pb.acme.test')`); err != nil {
		t.Fatalf("legacy row: %v", err)
	}

	s, err := New(db)
	if err != nil {
		t.Fatalf("New on legacy schema: %v", err)
	}
	c := s.Get()
	if c.ProductName != "Acme Broker" || c.FQDN != "pb.acme.test" {
		t.Fatalf("migration lost existing settings: %+v", c)
	}
	if c.AutoStart != DefaultAutoStart {
		t.Fatalf("migrated AutoStart = %q, want %q", c.AutoStart, DefaultAutoStart)
	}
	if err := s.SetAutoStart(AutoStartOff); err != nil {
		t.Fatalf("SetAutoStart after migration: %v", err)
	}
}
