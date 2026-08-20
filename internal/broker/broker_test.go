package broker

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// newTestManager returns a Manager rooted in a temp dir. BinPath points at the
// running test binary so ownsProcess can positively identify a live PID we
// control (os.Getpid) on both Linux (/proc/<pid>/exe) and other platforms.
func newTestManager(t *testing.T) *Manager {
	t.Helper()
	dir := t.TempDir()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	return &Manager{
		BinPath:    self,
		StatusPath: filepath.Join(dir, "packet_broker.status"),
		PidPath:    filepath.Join(dir, "packet_broker.pid"),
		LogPath:    filepath.Join(dir, "packet_broker.log"),
		RootDir:    dir,
		Mode:       ModeLibpcap,
	}
}

// deadPID returns the PID of a process that has certainly exited — the shape of
// a PID file left behind by a reboot or an OOM kill.
func deadPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("go", "version") // any short-lived, always-present binary
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot spawn a helper process: %v", err)
	}
	pid := cmd.Process.Pid
	_ = cmd.Wait()
	return pid
}

func TestReconcileClearsStaleRunningState(t *testing.T) {
	m := newTestManager(t)
	// Pre-reboot leftovers: status says running, PID belongs to nothing.
	if err := os.WriteFile(m.StatusPath, []byte("running"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.PidPath, []byte(strconv.Itoa(deadPID(t))), 0600); err != nil {
		t.Fatal(err)
	}

	if m.Reconcile() {
		t.Fatal("Reconcile reported the data plane as running for a dead PID")
	}
	if got := m.Status(); got != "stopped" {
		t.Fatalf("Status = %q, want %q", got, "stopped")
	}
	if _, err := os.Stat(m.PidPath); !os.IsNotExist(err) {
		t.Fatal("stale PID file was not removed")
	}
}

func TestReconcileKeepsLiveProcess(t *testing.T) {
	m := newTestManager(t)
	if err := os.WriteFile(m.PidPath, []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		t.Fatal(err)
	}

	if !m.Reconcile() {
		t.Fatal("Reconcile did not recognise a live data-plane process")
	}
	if got := m.Status(); got != "running" {
		t.Fatalf("Status = %q, want %q", got, "running")
	}
}

func TestStatusHealsStaleRunningFile(t *testing.T) {
	m := newTestManager(t)
	if err := os.WriteFile(m.StatusPath, []byte("running"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.PidPath, []byte(strconv.Itoa(deadPID(t))), 0600); err != nil {
		t.Fatal(err)
	}

	if got := m.Status(); got != "stopped" {
		t.Fatalf("Status = %q for a crashed data plane, want %q", got, "stopped")
	}
	// The correction must be persisted, not just returned.
	data, err := os.ReadFile(m.StatusPath)
	if err != nil || strings.TrimSpace(string(data)) != "stopped" {
		t.Fatalf("status file = %q (err %v), want %q", data, err, "stopped")
	}
	if _, err := os.Stat(m.PidPath); !os.IsNotExist(err) {
		t.Error("stale PID file was not removed")
	}
}

func TestStopIgnoresStalePID(t *testing.T) {
	if runtime.GOOS != "linux" {
		// Elsewhere there is no /proc to identify the process behind a PID, so
		// ownsProcess deliberately trusts any live PID.
		t.Skip("PID ownership check is Linux-only")
	}
	m := newTestManager(t)
	// A PID file naming a process that isn't ours must not be signalled: after
	// a reboot the recorded PID is very likely reused by something unrelated.
	m.BinPath = filepath.Join(m.RootDir, "packet_broker")
	if err := os.WriteFile(m.PidPath, []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := m.Status(); got != "stopped" {
		t.Fatalf("Status = %q, want %q", got, "stopped")
	}
	// Surviving this far means we did not SIGTERM ourselves.
}

func TestIsBrokerNameHandlesCommTruncation(t *testing.T) {
	m := &Manager{
		BinPath:   "/opt/packet-broker/packet_broker",
		AFXDPPath: "/opt/packet-broker/packet_broker_afxdp",
	}
	// /proc/<pid>/comm is capped at 15 characters.
	if !m.isBrokerName("packet_broker_a") {
		t.Error("truncated afxdp process name not recognised")
	}
	if !m.isBrokerName("packet_broker") {
		t.Error("libpcap process name not recognised")
	}
	if m.isBrokerName("sshd") {
		t.Error("unrelated process name recognised as the data plane")
	}
}
