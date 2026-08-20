package server

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"packet_broker/internal/appcfg"
	"packet_broker/internal/errx"
)

// Auto-start / supervision timings.
const (
	// superviseInterval is how often the "always" policy re-checks that the
	// data-plane process is still alive.
	superviseInterval = 15 * time.Second
	// maxSuperviseBackoff caps the wait between restart attempts so a data
	// plane that cannot start (missing NIC, no CAP_NET_RAW) doesn't respawn
	// every 15 seconds forever.
	maxSuperviseBackoff = 5 * time.Minute
)

// autoStartEnv is the environment override for the stored auto-start policy.
// It lets an appliance image or the systemd unit pin the behaviour without
// touching the database (off | restore | always, or 0/1).
const autoStartEnv = "PB_AUTOSTART"

// autoStartPolicy resolves the effective policy. The environment wins over the
// stored setting, which wins over the default (restore).
func (a *App) autoStartPolicy() string {
	if p := appcfg.NormalizeAutoStart(os.Getenv(autoStartEnv)); p != "" {
		return p
	}
	if a.appCfg != nil {
		if p := appcfg.NormalizeAutoStart(a.appCfg.Get().AutoStart); p != "" {
			return p
		}
	}
	return appcfg.DefaultAutoStart
}

// autoStartLocked reports whether PB_AUTOSTART is pinning the policy, in which
// case the UI setting is shown but has no effect.
func (a *App) autoStartLocked() bool {
	return appcfg.NormalizeAutoStart(os.Getenv(autoStartEnv)) != ""
}

// desiredState returns the operator's last explicit start/stop intent.
func (a *App) desiredState() string {
	if a.appCfg == nil {
		return appcfg.StateStopped
	}
	return a.appCfg.Get().DesiredState
}

// setDesiredState records the operator's intent; failures are logged rather
// than surfaced, since the start/stop itself has already succeeded.
func (a *App) setDesiredState(state string) {
	if a.appCfg == nil {
		return
	}
	if err := a.appCfg.SetDesiredState(state); err != nil {
		a.logErr("auto-start: recording desired state: " + err.Error())
	}
}

// applyAutoStart brings the data plane up at control-plane start-up according
// to the configured policy, and launches the supervisor when the policy is
// "always".
//
// Before deciding anything it reconciles the recorded status with the real
// process: after a reboot the status/PID files still describe the pre-reboot
// data plane, so without this the UI would show "running" over a dead data
// plane and the policy would decide there is nothing to start.
//
// It runs on its own goroutine: broker.Start blocks for a couple of seconds on
// the AF_XDP/DPDK liveness probe, and the UI should be up before then.
func (a *App) applyAutoStart() {
	go func() {
		policy := a.autoStartPolicy()

		if a.broker.Reconcile() {
			a.info("auto-start: data plane already running (PID=" + strconv.Itoa(a.broker.PID()) + ")")
			a.maybeSupervise(policy)
			return
		}

		switch policy {
		case appcfg.AutoStartOff:
			a.info("auto-start: disabled — data plane left stopped")
			return
		case appcfg.AutoStartRestore:
			if a.desiredState() != appcfg.StateRunning {
				a.info("auto-start: data plane was stopped before shutdown — leaving it stopped")
				return
			}
		case appcfg.AutoStartAlways:
			// "always" is itself the intent, so record it: a later restart
			// under the "restore" policy then behaves consistently.
			a.setDesiredState(appcfg.StateRunning)
		}

		if err := a.startDataPlane(); err != nil {
			a.logErr("auto-start: " + err.Error())
			return
		}
		a.info("auto-start: data plane started (policy=" + policy + ", PID=" + strconv.Itoa(a.broker.PID()) + ")")
		a.maybeSupervise(policy)
	}()
}

// startDataPlane performs the checks the UI's Start button performs, so the
// boot path and the button path cannot drift apart.
func (a *App) startDataPlane() error {
	bin := a.broker.ActiveBinPath()
	if _, err := os.Stat(bin); err != nil {
		return fmt.Errorf("data-plane binary not found: %s (mode=%s)", bin, a.broker.Mode)
	}
	a.rules.Ensure()
	return a.broker.Start()
}

// maybeSupervise starts the restart loop for the "always" policy, at most one
// at a time (applyAutoStart also runs when the policy is changed from the UI).
func (a *App) maybeSupervise(policy string) {
	if policy != appcfg.AutoStartAlways {
		return
	}
	a.superviseMu.Lock()
	defer a.superviseMu.Unlock()
	if a.supervising {
		return
	}
	a.supervising = true
	go func() {
		defer func() {
			a.superviseMu.Lock()
			a.supervising = false
			a.superviseMu.Unlock()
		}()
		a.superviseDataPlane()
	}()
}

// superviseDataPlane restarts the data plane if it dies while the operator
// wants it running. It is only active under the "always" policy — this is the
// data-plane counterpart of the unit's Restart=always, which only covers the
// control plane.
//
// An operator Stop clears the desired state, so the supervisor never fights the
// UI button. Repeated failures back off exponentially up to
// maxSuperviseBackoff so a data plane that cannot start doesn't spin.
func (a *App) superviseDataPlane() {
	tick := time.NewTicker(superviseInterval)
	defer tick.Stop()

	fails := 0
	var nextAttempt time.Time

	for {
		select {
		case <-a.autoStop:
			return
		case now := <-tick.C:
			if a.autoStartPolicy() != appcfg.AutoStartAlways {
				a.info("supervisor: policy is no longer \"always\" — supervisor stopped")
				return
			}
			if a.desiredState() != appcfg.StateRunning {
				fails = 0
				continue
			}
			if a.broker.Running() {
				fails = 0
				continue
			}
			if now.Before(nextAttempt) {
				continue
			}
			fails++
			backoff := superviseInterval << min(fails-1, 5)
			if backoff > maxSuperviseBackoff {
				backoff = maxSuperviseBackoff
			}
			nextAttempt = now.Add(backoff)

			a.logErr("supervisor: data plane is not running — restarting (attempt " + strconv.Itoa(fails) + ")")
			if err := a.startDataPlane(); err != nil {
				a.logErr("supervisor: restart failed: " + err.Error())
				continue
			}
			a.info("supervisor: data plane restarted (PID=" + strconv.Itoa(a.broker.PID()) + ")")
		}
	}
}

// handleAutoStartSave updates the data-plane auto-start policy from the
// appliance settings page.
func (a *App) handleAutoStartSave(w http.ResponseWriter, r *http.Request) {
	mode := r.FormValue("auto_start")
	if err := a.appCfg.SetAutoStart(mode); err != nil {
		errx.RedirectErrorMsg(w, r, "/admin/settings", "invalid auto-start mode")
		return
	}
	saved := a.appCfg.Get().AutoStart
	a.audit(r, "autostart", "data plane auto-start set to "+saved)

	// Switching to "always" while the UI is up should not need a reboot to
	// take effect, so bring the data plane up (and supervise it) right now.
	if saved == appcfg.AutoStartAlways && !a.autoStartLocked() {
		a.applyAutoStart()
	}
	if a.autoStartLocked() {
		errx.RedirectSuccess(w, r, "/admin/settings", "Auto-start saved, but "+autoStartEnv+" overrides it")
		return
	}
	errx.RedirectSuccess(w, r, "/admin/settings", "Auto-start updated")
}
