package auth

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestConcurrentAuthNoDeadlock hammers the shared SQLite handle from many
// goroutines at once. Run with -race it guards against data races in the
// store; the timeout guards against a connection-pool deadlock of the kind
// that froze the UI in production (a single nested query on MaxOpenConns(1)).
func TestConcurrentAuthNoDeadlock(t *testing.T) {
	s, err := New(filepath.Join(t.TempDir(), "users.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser("alice", "password123", RoleUser); err != nil {
		t.Fatal(err)
	}

	// The deadlock we guard against was about concurrent DB *queries*
	// contending for the connection pool (bcrypt runs after the connection is
	// released, so it isn't the contended resource). Hammer the pool with many
	// cheap concurrent reads, plus one real bcrypt login per goroutine for
	// realism. Completion within the timeout proves the pool doesn't wedge.
	done := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = s.Authenticate("alice", "password123") // one real bcrypt path
				for j := 0; j < 40; j++ {
					_, _ = s.UserCount() // pure query → pool contention
				}
			}()
		}
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("concurrent auth deadlocked or starved on the DB pool")
	}
}
