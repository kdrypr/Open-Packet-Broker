// Package capture manages tcpdump packet capture sessions.
package capture

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ── Types ─────────────────────────────────────────────────────────────────────

// Session represents one capture run.
type Session struct {
	ID        string    `json:"id"`
	Interface string    `json:"interface"`
	Filter    string    `json:"filter"`
	Status    string    `json:"status"` // "recording", "complete", "error"
	StartedAt time.Time `json:"started_at"`
	StoppedAt time.Time `json:"stopped_at,omitempty"`
	FileSize  int64     `json:"file_size"`
	FilePath  string    `json:"-"`
	Error     string    `json:"error,omitempty"`
	cmd       *exec.Cmd
}

// ── Manager ───────────────────────────────────────────────────────────────────

const maxConcurrent = 3

// Manager handles starting, stopping, and listing capture sessions.
type Manager struct {
	mu         sync.Mutex
	sessions   map[string]*Session
	captureDir string
	counter    int
}

// NewManager creates a capture manager. captureDir is where PCAP files are stored.
func NewManager(captureDir string) *Manager {
	os.MkdirAll(captureDir, 0o750)
	return &Manager{
		sessions:   make(map[string]*Session),
		captureDir: captureDir,
	}
}

// Start begins a new tcpdump capture.
func (m *Manager) Start(iface, filter string, maxSeconds int) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check concurrency limit
	active := 0
	for _, s := range m.sessions {
		if s.Status == "recording" {
			active++
		}
	}
	if active >= maxConcurrent {
		return "", fmt.Errorf("maximum %d concurrent captures reached", maxConcurrent)
	}

	if iface == "" {
		return "", errors.New("interface is required")
	}
	// Validate interface name (prevent injection)
	for _, c := range iface {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return "", fmt.Errorf("invalid interface name: %q", iface)
		}
	}
	// Validate BPF filter (block shell metacharacters)
	if filter != "" {
		for _, bad := range []string{";", "`", "$", "{", "}", "\\", "'", "\"", "|", ">", "<"} {
			if strings.Contains(filter, bad) {
				return "", fmt.Errorf("filter contains forbidden character: %s", bad)
			}
		}
		if len(filter) > 256 {
			return "", errors.New("filter too long (max 256 chars)")
		}
	}
	if maxSeconds <= 0 || maxSeconds > 300 {
		maxSeconds = 60
	}

	m.counter++
	// 128-bit random ID — captures may contain credentials, so the URL
	// "/captures/{id}/download" must not be guessable by another admin
	// (or by an unauthenticated path-traversal attempt).
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return "", fmt.Errorf("capture id: %w", err)
	}
	id := "cap_" + hex.EncodeToString(idBytes)
	pcapPath := filepath.Join(m.captureDir, id+".pcap")

	args := []string{"-i", iface, "-w", pcapPath, "-c", "100000"}
	if filter != "" {
		// "--" terminates option parsing so a filter beginning with '-'
		// (e.g. "-r") can't be mistaken for a tcpdump flag.
		args = append(args, "--", filter)
	}

	cmd := exec.Command("tcpdump", args...)
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("tcpdump: %w", err)
	}

	sess := &Session{
		ID:        id,
		Interface: iface,
		Filter:    filter,
		Status:    "recording",
		StartedAt: time.Now(),
		FilePath:  pcapPath,
		cmd:       cmd,
	}
	m.sessions[id] = sess

	// Auto-stop after maxSeconds
	go func() {
		timer := time.NewTimer(time.Duration(maxSeconds) * time.Second)
		defer timer.Stop()

		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()

		select {
		case err := <-done:
			m.mu.Lock()
			sess.Status = "complete"
			sess.StoppedAt = time.Now()
			if err != nil && sess.Error == "" {
				// tcpdump exits with status when killed, ignore
			}
			sess.FileSize = fileSize(pcapPath)
			m.mu.Unlock()
		case <-timer.C:
			cmd.Process.Signal(os.Interrupt)
			<-done
			m.mu.Lock()
			sess.Status = "complete"
			sess.StoppedAt = time.Now()
			sess.FileSize = fileSize(pcapPath)
			m.mu.Unlock()
		}
	}()

	return id, nil
}

// Stop terminates a running capture.
func (m *Manager) Stop(id string) error {
	m.mu.Lock()
	sess, ok := m.sessions[id]
	if !ok {
		m.mu.Unlock()
		return errors.New("session not found")
	}
	// Read Status + cmd under the lock — the auto-stop goroutine mutates them
	// under the same mutex, so reading them unlocked was a data race.
	recording := sess.Status == "recording"
	cmd := sess.cmd
	m.mu.Unlock()
	if !recording {
		return errors.New("capture not running")
	}
	if cmd != nil && cmd.Process != nil {
		cmd.Process.Signal(os.Interrupt)
	}
	return nil
}

// List returns all sessions, newest first.
func (m *Manager) List() []Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		cp := *s
		cp.cmd = nil
		if cp.Status == "recording" {
			cp.FileSize = fileSize(cp.FilePath)
		}
		out = append(out, cp)
	}
	// Sort newest first
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].StartedAt.After(out[i].StartedAt) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// GetPath returns the file path for download. Returns error if not found.
func (m *Manager) GetPath(id string) (string, error) {
	m.mu.Lock()
	sess, ok := m.sessions[id]
	m.mu.Unlock()
	if !ok {
		return "", errors.New("session not found")
	}
	return sess.FilePath, nil
}

// Delete removes a completed capture and its file.
func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	sess, ok := m.sessions[id]
	if !ok {
		m.mu.Unlock()
		return errors.New("session not found")
	}
	if sess.Status == "recording" {
		m.mu.Unlock()
		return errors.New("stop capture before deleting")
	}
	delete(m.sessions, id)
	m.mu.Unlock()
	os.Remove(sess.FilePath)
	return nil
}

func fileSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.Size()
}
