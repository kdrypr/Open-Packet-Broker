package server

import (
	"net/http"
	"strings"

	"packet_broker/internal/errx"
)

// ---------------------------------------------------------------------------
// Health Checks (F8)
// ---------------------------------------------------------------------------

func (a *App) handleHealthChecks(w http.ResponseWriter, r *http.Request) {
	data := a.baseData(r, "healthcheck")
	data.HealthChecks, _ = a.healthChecks.List()
	data.FlashError = r.URL.Query().Get("error")
	data.FlashSuccess = r.URL.Query().Get("success")
	a.render(w, "healthcheck.html", data)
}
func (a *App) handleHealthCheckCreate(w http.ResponseWriter, r *http.Request) {
	port := strings.TrimSpace(r.FormValue("port"))
	if err := a.checkDataPlane(port); err != nil {
		errx.RedirectError(w, r, "/health-checks", err)
		return
	}
	autoDisable := r.FormValue("auto_disable") == "1"
	if err := a.healthChecks.Create(port, autoDisable); err != nil {
		errx.RedirectError(w, r, "/health-checks", err)
		return
	}
	errx.RedirectSuccess(w, r, "/health-checks", "Port monitor added")
}
func (a *App) handleHealthCheckDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := errx.ParseID(r, "id")
	if !ok {
		errx.BadRequest(w, "invalid id")
		return
	}
	a.healthChecks.Delete(id)
	http.Redirect(w, r, "/health-checks", http.StatusSeeOther)
}
func (a *App) handleHealthCheckToggle(w http.ResponseWriter, r *http.Request) {
	id, ok := errx.ParseID(r, "id")
	if !ok {
		errx.BadRequest(w, "invalid id")
		return
	}
	a.healthChecks.Toggle(id)
	http.Redirect(w, r, "/health-checks", http.StatusSeeOther)
}
