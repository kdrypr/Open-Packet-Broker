package server

import (
	"net/http"
	"strconv"
	"strings"

	"packet_broker/internal/errx"
	"packet_broker/internal/sanitize"
)

// ---------------------------------------------------------------------------
// Alerts (Feature 7)
// ---------------------------------------------------------------------------

func (a *App) handleAlerts(w http.ResponseWriter, r *http.Request) {
	data := a.baseData(r, "alerts")
	data.AlertRules, _ = a.alerts.ListRules()
	data.AlertEvents, _ = a.alerts.ListEvents(50)
	data.FlashError = r.URL.Query().Get("error")
	data.FlashSuccess = r.URL.Query().Get("success")
	a.render(w, "alerts.html", data)
}

func (a *App) handleAlertCreate(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	metric := r.FormValue("metric")
	threshold, _ := strconv.ParseFloat(r.FormValue("threshold"), 64)
	operator := r.FormValue("operator")
	iface := strings.TrimSpace(r.FormValue("interface"))
	webhook := strings.TrimSpace(r.FormValue("webhook_url"))

	fail := func(msg string) {
		errx.RedirectErrorMsg(w, r, "/alerts", msg)
	}
	if name == "" {
		fail("Name is required")
		return
	}
	// SSRF protection: validate webhook URL
	if webhook != "" {
		if wh, err := sanitize.WebhookURL(webhook); err != nil {
			fail(err.Error())
			return
		} else {
			webhook = wh
		}
	}
	if err := a.alerts.CreateRule(name, metric, operator, iface, webhook, threshold); err != nil {
		errx.RedirectError(w, r, "/alerts", err)
		return
	}
	a.info("Alert rule created: " + name)
	errx.RedirectSuccess(w, r, "/alerts", "Alert created")
}

func (a *App) handleAlertDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := errx.ParseID(r, "id")
	if !ok {
		errx.BadRequest(w, "invalid id")
		return
	}
	a.alerts.DeleteRule(id)
	http.Redirect(w, r, "/alerts", http.StatusSeeOther)
}

func (a *App) handleAlertToggle(w http.ResponseWriter, r *http.Request) {
	id, ok := errx.ParseID(r, "id")
	if !ok {
		errx.BadRequest(w, "invalid id")
		return
	}
	a.alerts.ToggleRule(id)
	http.Redirect(w, r, "/alerts", http.StatusSeeOther)
}

func (a *App) handleAlertAcknowledge(w http.ResponseWriter, r *http.Request) {
	id, ok := errx.ParseID(r, "id")
	if !ok {
		errx.BadRequest(w, "invalid id")
		return
	}
	a.alerts.AcknowledgeEvent(id)
	http.Redirect(w, r, "/alerts", http.StatusSeeOther)
}
