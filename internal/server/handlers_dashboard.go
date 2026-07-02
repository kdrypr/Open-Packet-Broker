package server

import (
	"net/http"
	"os"
	"strconv"

	"packet_broker/internal/logs"
)

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	ruleList, _ := a.rules.Parse()
	opsOnly := !a.authStore.IsAdmin(r)
	recent := logs.ReadRecent(a.logPath, 5, opsOnly)

	data := a.baseData(r, "index")
	data.RuleCount = len(ruleList)
	data.RecentLogs = recent
	data.DefaultAdmin = a.defaultAdminActive()

	if a.sysinfo != nil {
		sys := a.sysinfo.Current()
		data.Uptime = sys.UptimeStr
		data.CPUPercent = sys.CPUPercent
		data.MemPercent = sys.MemPercent
		data.MemTotal = fmtBytes(sys.MemTotal)
		data.MemUsed = fmtBytes(sys.MemUsed)
	}
	a.render(w, "index.html", data)
}

// ---------------------------------------------------------------------------
// Broker control
// ---------------------------------------------------------------------------

func (a *App) handleStart(w http.ResponseWriter, r *http.Request) {
	if a.broker.Status() == "running" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	bin := a.broker.ActiveBinPath()
	if _, err := os.Stat(bin); os.IsNotExist(err) {
		http.Error(w, "Binary not found: "+bin+" (mode="+a.broker.Mode+")", http.StatusInternalServerError)
		return
	}
	// Note: in AF_XDP mode broker.Start() binds XSK sockets to ALL data-plane
	// interfaces at boot (via broker.DataPlaneIfaces). That means rules can be
	// added / edited / removed freely at runtime without restarting — same as
	// commercial appliance behavior.
	a.rules.Ensure()
	if err := a.broker.Start(); err != nil {
		a.logErr("Start failed: " + err.Error())
		http.Error(w, "Start failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	a.info("Broker started. PID=" + strconv.Itoa(a.broker.PID()))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) handleStop(w http.ResponseWriter, r *http.Request) {
	if a.broker.Status() == "stopped" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	pid := a.broker.PID()
	if err := a.broker.Stop(); err != nil {
		a.logErr("Stop failed: " + err.Error())
		http.Error(w, "Stop failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	a.info("Broker stopped. PID=" + strconv.Itoa(pid))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
