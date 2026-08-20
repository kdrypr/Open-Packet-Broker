// Package broker manages the lifecycle of the C packet broker binary.
//
// Data plane mode is selected at process start via the BROKER_MODE
// environment variable:
//
//	BROKER_MODE=libpcap   → spawn packet_broker        (default, max compatibility)
//	BROKER_MODE=afxdp     → spawn packet_broker_afxdp  (zero-copy XDP socket fast path)
//	BROKER_MODE=dpdk      → spawn packet_broker_dpdk   (DPDK PMD; requires hugepages
//	                        + NICs bound to a DPDK driver, set up out of band. The
//	                        EAL args come from PB_DPDK_EAL, default "-l 0-3 -n 4")
//
// The mode is fixed for the lifetime of the UI process — change it by
// editing /etc/systemd/system/packet-broker.service (or .env) and
// restarting packet-broker.service.
package broker

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"packet_broker/internal/netifaces"
)

// Mode constants.
const (
	ModeLibpcap = "libpcap"
	ModeAFXDP   = "afxdp"
	ModeDPDK    = "dpdk"
)

// Manager holds paths required to control the broker binary.
type Manager struct {
	BinPath    string // libpcap binary (always present; default)
	AFXDPPath  string // afxdp binary (used when Mode == ModeAFXDP)
	DPDKPath   string // dpdk binary (used when Mode == ModeDPDK)
	StatusPath string
	PidPath    string
	LogPath    string
	RootDir    string
	Mode       string // libpcap | afxdp | dpdk
}

// ActiveBinPath returns the binary that will be launched for the current Mode. If the
// mode-specific binary isn't actually present (e.g. BROKER_MODE=afxdp was set but only
// the libpcap binary was deployed), it falls back to the libpcap binary so capture
// never silently dies — making "default to AF_XDP" safe on any host.
func (m *Manager) ActiveBinPath() string {
	switch m.Mode {
	case ModeAFXDP:
		if fileExists(m.AFXDPPath) {
			return m.AFXDPPath
		}
	case ModeDPDK:
		if fileExists(m.DPDKPath) {
			return m.DPDKPath
		}
	}
	return m.BinPath
}

// EffectiveMode reports the mode that will actually run, accounting for the
// binary-present fallback (afxdp/dpdk → libpcap when their binary is missing).
func (m *Manager) EffectiveMode() string {
	switch m.Mode {
	case ModeAFXDP:
		if fileExists(m.AFXDPPath) {
			return ModeAFXDP
		}
	case ModeDPDK:
		if fileExists(m.DPDKPath) {
			return ModeDPDK
		}
	}
	return ModeLibpcap
}

func fileExists(p string) bool {
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}

// DataPlaneIfaces enumerates every physical NIC that is NOT a management
// interface — exactly the set the AF_XDP binary should bind XSK sockets to
// at startup. By attaching to all data-plane ports up front, customers can
// add/edit rules referencing any port without restarting the broker.
//
// The mgmt-iface detection logic is shared with the UI in the netifaces
// package so what the UI offers as data-plane == what this binary binds.
func (m *Manager) DataPlaneIfaces() []string {
	return netifaces.DataPlane()
}

// Status returns "running" or "stopped".
//
// The status file alone cannot be trusted: it is written by Start/Stop and by
// the data plane itself, so a crash, an OOM kill or a host reboot leaves it
// saying "running" with nothing behind it — the dashboard then shows a green
// pill for a data plane that is dropping every packet. A "running" claim is
// therefore confirmed against the process, and a stale claim is corrected on
// the spot so the UI, the cluster heartbeat and the Start/Stop buttons all
// agree with reality.
func (m *Manager) Status() string {
	data, err := os.ReadFile(m.StatusPath)
	if err != nil || strings.TrimSpace(string(data)) != "running" {
		return "stopped"
	}
	if m.Running() {
		return "running"
	}
	m.markStopped()
	return "stopped"
}

// markStopped records "stopped" and drops the PID file, which is no longer
// naming anything of ours.
func (m *Manager) markStopped() {
	_ = os.Remove(m.PidPath)
	_ = os.WriteFile(m.StatusPath, []byte("stopped"), 0600)
}

// Running reports whether the data-plane process is actually alive right now,
// as opposed to what the status file claims.
func (m *Manager) Running() bool {
	return m.ownsProcess(m.PID())
}

// Reconcile makes the recorded status agree with reality and reports whether
// the data plane is running. It exists because the status/PID files survive
// events the process does not: a hard reboot or an OOM kill leaves
// packet_broker.status saying "running" with nothing behind it, so the UI shows
// a green pill for a data plane that is dropping every packet.
//
// Call it once at control-plane start-up, before applying the auto-start policy.
func (m *Manager) Reconcile() bool {
	if m.Running() {
		_ = os.WriteFile(m.StatusPath, []byte("running"), 0600)
		return true
	}
	m.markStopped()
	return false
}

// ownsProcess reports whether pid is alive *and* is one of our data-plane
// binaries. The identity check matters after a reboot: PIDs are reused from a
// low number on every boot, so a bare kill(pid, 0) on a stale PID file happily
// reports "running" — and would let Stop send SIGTERM to an unrelated process.
//
// It is deliberately conservative: only a *proven* mismatch (we could read the
// process's executable or name and it isn't ours) returns false. When /proc is
// unreadable — non-Linux, a hardened container — an alive PID is assumed ours,
// which keeps Stop working at the cost of not detecting reuse.
func (m *Manager) ownsProcess(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	if proc.Signal(syscall.Signal(0)) != nil {
		return false // no such process (or not ours to signal)
	}
	if runtime.GOOS != "linux" {
		return true
	}
	procDir := "/proc/" + strconv.Itoa(pid)
	if isZombie(procDir) {
		return false // exited, just not reaped yet
	}
	if exe, err := os.Readlink(procDir + "/exe"); err == nil {
		return m.isBrokerPath(exe)
	}
	// No /proc/<pid>/exe (permissions): fall back to the process name. Note
	// /proc/<pid>/comm is truncated to 15 chars, hence the prefix compare.
	comm, err := os.ReadFile(procDir + "/comm")
	if err != nil {
		return true // can't tell — treat an alive PID as ours
	}
	return m.isBrokerName(strings.TrimSpace(string(comm)))
}

// isBrokerPath reports whether an executable path is one of our data-plane
// binaries, comparing resolved paths so a symlinked deployment dir still matches.
func (m *Manager) isBrokerPath(exe string) bool {
	exe = strings.TrimSuffix(exe, " (deleted)") // binary replaced by an upgrade
	resolved := exe
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		resolved = r
	}
	for _, p := range m.binPaths() {
		if p == exe || p == resolved {
			return true
		}
		if r, err := filepath.EvalSymlinks(p); err == nil && (r == exe || r == resolved) {
			return true
		}
	}
	return m.isBrokerName(filepath.Base(exe))
}

// isBrokerName reports whether a process name matches one of our binaries,
// tolerating the 15-char truncation of /proc/<pid>/comm.
func (m *Manager) isBrokerName(name string) bool {
	const commMax = 15 // TASK_COMM_LEN - 1
	for _, p := range m.binPaths() {
		base := filepath.Base(p)
		if name == base || (len(base) > commMax && name == base[:commMax]) {
			return true
		}
	}
	return false
}

// isZombie reports whether the process behind procDir has exited but not been
// reaped. Its state is the third field of /proc/<pid>/stat, which is parsed
// from the last ")" because the second field (the comm) can itself contain
// spaces and parentheses.
func isZombie(procDir string) bool {
	stat, err := os.ReadFile(procDir + "/stat")
	if err != nil {
		return false
	}
	i := strings.LastIndex(string(stat), ")")
	if i < 0 {
		return false
	}
	fields := strings.Fields(string(stat)[i+1:])
	return len(fields) > 0 && fields[0] == "Z"
}

func (m *Manager) binPaths() []string {
	out := make([]string, 0, 3)
	for _, p := range []string{m.BinPath, m.AFXDPPath, m.DPDKPath} {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Start launches the broker binary as a detached process.
// It writes stdout/stderr to LogPath and records the PID.
// Before starting, brings up all interfaces referenced in rules.conf.
//
// For Mode == ModeAFXDP, the binary is invoked with positional iface
// arguments collected from rules.conf (the C side needs to know which
// ports to bind XSK sockets on).
func (m *Manager) Start() error {
	bin := m.ActiveBinPath()
	if err := os.Chmod(bin, 0755); err != nil {
		_ = err
	}
	// Use the EFFECTIVE mode (after the binary-present fallback) so a libpcap binary
	// is never handed AF_XDP/DPDK-shaped arguments.
	mode := m.EffectiveMode()

	// Auto-UP interfaces from rules.conf before starting. Skipped for DPDK:
	// its NICs are bound to a DPDK driver and are not kernel-visible.
	if mode != ModeDPDK {
		m.bringUpInterfaces()
	}

	args := []string(nil)
	env := os.Environ()
	switch mode {
	case ModeAFXDP:
		args = m.DataPlaneIfaces()
	case ModeDPDK:
		// EAL args (core list, PCI allow-list, …) are deployment-specific and
		// supplied by the operator via PB_DPDK_EAL. Selecting dpdk mode is the
		// explicit opt-in the binary's gate requires.
		eal := strings.Fields(strings.TrimSpace(os.Getenv("PB_DPDK_EAL")))
		if len(eal) == 0 {
			eal = []string{"-l", "0-3", "-n", "4"}
		}
		args = append(eal, "--")
		env = append(env, "PB_DPDK_EXPERIMENTAL=1")
	}

	pid, err := m.spawn(bin, args, env)
	if err != nil {
		return err
	}

	// AF_XDP/DPDK can fail at RUNTIME even when the binary is present — missing
	// CAP_SYS_ADMIN, no AF_XDP in the sandbox, an unsupported kernel. If the process
	// dies within a short grace window, fall back to the libpcap binary so capture
	// never silently goes blind. This is what makes "use AF_XDP by default, even on a
	// virtual NIC" safe: it runs AF_XDP when it can, libpcap when it can't.
	if mode != ModeLibpcap && !processAliveAfter(pid, 2*time.Second) {
		log.Printf("broker: %s mode exited immediately — falling back to libpcap (check CAP_SYS_ADMIN / AF_XDP sandbox / kernel)", mode)
		m.bringUpInterfaces()
		pid, err = m.spawn(m.BinPath, nil, os.Environ())
		if err != nil {
			return err
		}
	}

	os.WriteFile(m.PidPath, []byte(strconv.Itoa(pid)), 0600)
	os.WriteFile(m.StatusPath, []byte("running"), 0600)
	return nil
}

// spawn launches a broker binary detached, with stdout/stderr appended to the broker
// log, and returns its PID.
func (m *Manager) spawn(bin string, args, env []string) (int, error) {
	lf, err := os.OpenFile(m.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return 0, err
	}
	defer lf.Close()
	cmd := exec.Command(bin, args...)
	cmd.Dir = m.RootDir
	cmd.Env = env
	cmd.Stdout = lf
	cmd.Stderr = lf
	// Detach from parent process group so the broker survives UI restarts.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	// Reap the child when it exits. Without this it lingers as a zombie for as
	// long as the UI runs, and a zombie answers kill(pid, 0) — so a dead data
	// plane would still look alive to Status/Stop/the supervisor.
	go func() { _ = cmd.Wait() }()
	return cmd.Process.Pid, nil
}

// processAliveAfter reports whether pid is still running after grace — used to detect
// a data-plane binary that crashed on startup (so we can fall back).
func processAliveAfter(pid int, grace time.Duration) bool {
	time.Sleep(grace)
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

// Stop performs a graceful shutdown of the broker:
//
//  1. Send SIGTERM (C binary's signal handler closes libpcap/XSK cleanly)
//  2. Poll the PID for up to 3 seconds, checking it has exited
//  3. If still alive, send SIGKILL as last resort
//
// Marks status as "stopped" and removes the PID file regardless of path taken.
func (m *Manager) Stop() error {
	defer os.WriteFile(m.StatusPath, []byte("stopped"), 0600)
	defer os.Remove(m.PidPath)

	data, err := os.ReadFile(m.PidPath)
	if err != nil {
		return nil // nothing to stop
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return nil
	}
	if !m.ownsProcess(pid) {
		return nil // stale PID file (host rebooted / process already gone)
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return nil
	}

	// SIGTERM first — gives the C binary's signal handler time to flush
	// libpcap buffers, close XSK sockets, and write final stats.
	_ = proc.Signal(syscall.SIGTERM)

	// Poll for exit (kill -0 sends signal 0 = liveness check)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := proc.Signal(syscall.Signal(0)); err != nil {
			return nil // process gone
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Still alive — escalate to SIGKILL
	_ = proc.Kill()
	return nil
}

// bringUpInterfaces brings UP all physical network interfaces on the system
// (excluding loopback) and enables promiscuous mode. This ensures all ports
// are visible in topology and ready for packet capture before any rules exist.
func (m *Manager) bringUpInterfaces() {
	if runtime.GOOS != "linux" {
		return
	}
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if name == "lo" {
			continue
		}
		exec.Command("ip", "link", "set", name, "up").Run()
		exec.Command("ip", "link", "set", name, "promisc", "on").Run()
	}
}

// PID returns the current broker PID, or 0 if not running.
func (m *Manager) PID() int {
	data, err := os.ReadFile(m.PidPath)
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	return pid
}
