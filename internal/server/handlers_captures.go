package server

import (
	"net/http"
	"strconv"
	"strings"

	"packet_broker/internal/errx"
)

// ---------------------------------------------------------------------------
// Captures (Feature 4)
// ---------------------------------------------------------------------------

func (a *App) handleCaptures(w http.ResponseWriter, r *http.Request) {
	data := a.baseData(r, "captures")
	data.Captures = a.captures.List()
	data.FlashError = r.URL.Query().Get("error")
	data.FlashSuccess = r.URL.Query().Get("success")
	a.render(w, "captures.html", data)
}

func (a *App) handleCaptureStart(w http.ResponseWriter, r *http.Request) {
	iface := strings.TrimSpace(r.FormValue("interface"))
	if err := a.checkDataPlane(iface); err != nil {
		errx.RedirectError(w, r, "/captures", err)
		return
	}
	filter := strings.TrimSpace(r.FormValue("filter"))
	maxSec, _ := strconv.Atoi(r.FormValue("max_seconds"))
	if maxSec <= 0 {
		maxSec = 60
	}

	id, err := a.captures.Start(iface, filter, maxSec)
	if err != nil {
		errx.RedirectError(w, r, "/captures", err)
		return
	}
	a.info("Capture started: " + id + " on " + iface)
	errx.RedirectSuccess(w, r, "/captures", "Capture started")
}

func (a *App) handleCaptureStop(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a.captures.Stop(id)
	http.Redirect(w, r, "/captures", http.StatusSeeOther)
}

func (a *App) handleCaptureDownload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	path, err := a.captures.GetPath(id)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=\""+id+".pcap\"")
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, path)
}

func (a *App) handleCaptureDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a.captures.Delete(id)
	errx.RedirectSuccess(w, r, "/captures", "Capture deleted")
}
