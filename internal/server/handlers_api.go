package server

import (
	"encoding/json"
	"net/http"
)

// ---------------------------------------------------------------------------
// JSON API endpoints
// ---------------------------------------------------------------------------

func (a *App) handleAPIStats(w http.ResponseWriter, r *http.Request) {
	result := map[string]any{
		"rates":     a.stats.Rates(),
		"stats":     a.stats.Stats(),
		"link_info": a.stats.LinkInfo(),
	}
	// In AF_XDP mode the kernel /proc/net/dev counters miss most of the
	// traffic because XDP redirects bypass the stack. Surface the data-plane
	// binary's own counters under "dp" so the UI can fall back to them.
	if a.dpStats != nil {
		result["dp"] = a.dpStats.Refresh()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (a *App) handleAPISparklines(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(a.stats.AllSparklines())
}

func (a *App) handleAPISystem(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(a.sysinfo.Current())
}

func (a *App) handleAPITraffic24h(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(a.sysinfo.TrafficHistory())
}

func (a *App) handleAPICaptures(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(a.captures.List())
}

func (a *App) handleAPIAlertEvents(w http.ResponseWriter, r *http.Request) {
	events, _ := a.alerts.ListEvents(20)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"events":  events,
		"unacked": a.alerts.UnackedCount(),
	})
}

// REST API for backups
func (a *App) handleAPIBackupsList(w http.ResponseWriter, r *http.Request) {
	list, _ := a.backups.List()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}
