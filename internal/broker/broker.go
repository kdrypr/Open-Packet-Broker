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

// Status returns "running" or "stopped" by reading packet_broker.status.
func (m *Manager) Status() string {
	data, err := os.ReadFile(m.StatusPath)
	if err != nil {
		return "stopped"
	}
	return strings.TrimSpace(string(data))
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
