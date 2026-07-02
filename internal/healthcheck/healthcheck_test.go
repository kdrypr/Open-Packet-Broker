package healthcheck

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// TestListNoNestedQueryDeadlock is the regression guard for the production
// incident: List() ran a per-row QueryRow INSIDE its own open Rows loop. On a
// single-connection pool that self-deadlocks forever (the open Rows holds the
// only connection; the nested query waits for one that never frees), which
// froze every DB user — login included. We pin MaxOpenConns(1) so the old
// code would hang here; the fixed List (drain + close Rows, then run the
// COUNT queries) must return promptly even under concurrent callers.
func TestListNoNestedQueryDeadlock(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "hc.db")+"?_pragma=busy_timeout(2000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1) // the unforgiving setting that exposed the bug

	m, err := New(db, func() map[string]string { return map[string]string{} }, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	// Rows must exist so the loop body — and the COUNT subquery — actually run.
	for _, p := range []string{"eth0", "eth1", "eth2"} {
		if err := m.Create(p, true); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO auto_disabled_rules (port, rule_idx) VALUES ('eth0', 1)`); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		for i := 0; i < 300; i++ {
			if _, err := m.List(); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("List() returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("List() deadlocked on a single-connection pool — nested-query regression is back")
	}
}
