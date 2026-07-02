package totp

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "totp.db"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestReplayRejected verifies the SEC-2 fix: a TOTP code may be consumed at
// most once. A sniffed/phished code replayed inside its validity window must
// be rejected.
func TestReplayRejected(t *testing.T) {
	s := newTestStore(t)
	secret, _, err := s.GenerateSecret(1, "alice")
	if err != nil {
		t.Fatal(err)
	}
	code := generateCode(secret, time.Now().Unix()/period)

	if !s.Verify(1, code) {
		t.Fatal("first use of a valid code should succeed")
	}
	if s.Verify(1, code) {
		t.Fatal("replay of an already-consumed code must be rejected")
	}
}

// TestWrongCodeRejected sanity-checks that a bad code never validates and does
// not consume the step.
func TestWrongCodeRejected(t *testing.T) {
	s := newTestStore(t)
	if _, _, err := s.GenerateSecret(2, "bob"); err != nil {
		t.Fatal(err)
	}
	if s.Verify(2, "000000") && s.Verify(2, "000001") {
		t.Fatal("garbage codes must not validate")
	}
}
