package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"packet_broker/internal/cluster"
	"packet_broker/internal/errx"
)

// ---------------------------------------------------------------------------
// Cluster (F10)
// ---------------------------------------------------------------------------

func (a *App) handleCluster(w http.ResponseWriter, r *http.Request) {
	data := a.baseData(r, "cluster")
	data.ClusterConfig = a.clusterMgr.GetConfig()
	data.ClusterNodes, _ = a.clusterMgr.ListNodes()
	data.FlashError = r.URL.Query().Get("error")
	data.FlashSuccess = r.URL.Query().Get("success")
	a.render(w, "cluster.html", data)
}
func (a *App) handleClusterConfig(w http.ResponseWriter, r *http.Request) {
	mode := r.FormValue("mode")
	ctrlURL := strings.TrimSpace(r.FormValue("controller_url"))
	nodeName := strings.TrimSpace(r.FormValue("node_name"))
	nodeAddr := strings.TrimSpace(r.FormValue("node_address"))
	secret := strings.TrimSpace(r.FormValue("secret"))
	if err := a.clusterMgr.SaveConfig(mode, ctrlURL, nodeName, nodeAddr, secret); err != nil {
		errx.RedirectError(w, r, "/cluster", err)
		return
	}
	a.clusterMgr.Start()
	a.info("Cluster config updated: mode=" + mode)
	errx.RedirectSuccess(w, r, "/cluster", "Cluster configuration saved")
}

// handleClusterRegenSecret rotates the controller's shared secret.
// All previously-provisioned nodes must be updated to the new value or
// their heartbeats will be rejected.
func (a *App) handleClusterRegenSecret(w http.ResponseWriter, r *http.Request) {
	if _, err := a.clusterMgr.RegenerateSecret(); err != nil {
		errx.RedirectError(w, r, "/cluster", err)
		return
	}
	a.info("Cluster secret regenerated")
	errx.RedirectSuccess(w, r, "/cluster", "New secret generated — re-provision nodes")
}

// handleClusterHeartbeat receives heartbeats from cluster nodes. Auth
// is via shared secret in `X-Cluster-Secret` header (constant-time
// compared in cluster.ValidateHeartbeatAuth). This endpoint is exempt
// from session+CSRF middleware because nodes can't mint browser-mint
// cookies; the secret is the auth.
func (a *App) handleClusterHeartbeat(w http.ResponseWriter, r *http.Request) {
	if err := a.clusterMgr.ValidateHeartbeatAuth(r); err != nil {
		// Quiet 401 — don't leak whether the secret was wrong vs the
		// node identity was unknown.
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	var hb cluster.Heartbeat
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&hb); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if hb.Name == "" || hb.Address == "" {
		http.Error(w, "Invalid heartbeat: name+address required", http.StatusBadRequest)
		return
	}
	if err := a.clusterMgr.RegisterNode(hb); err != nil {
		a.logErr("Cluster register: " + err.Error())
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}
func (a *App) handleClusterNodes(w http.ResponseWriter, r *http.Request) {
	nodes, _ := a.clusterMgr.ListNodes()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(nodes)
}
