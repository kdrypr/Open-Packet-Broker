package server

import (
	"net/http"
	"path/filepath"
	"strings"

	"packet_broker/internal/dpi"
	"packet_broker/internal/errx"
	"packet_broker/internal/sanitize"
)

// ---------------------------------------------------------------------------
// DPI / Application Intelligence (#4)
// ---------------------------------------------------------------------------

func (a *App) handleDPI(w http.ResponseWriter, r *http.Request) {
	data := a.baseData(r, "dpi")
	data.DPIRules, _ = a.dpiStore.ListRules()
	data.DPIStats = a.dpiStore.GetStats()
	data.FlashError = r.URL.Query().Get("error")
	data.FlashSuccess = r.URL.Query().Get("success")
	a.render(w, "dpi.html", data)
}
func (a *App) handleDPICreate(w http.ResponseWriter, r *http.Request) {
	fail := func(msg string) {
		errx.RedirectErrorMsg(w, r, "/dpi", msg)
	}
	// These values are written verbatim into dpi.conf, which the root C data
	// plane parses. Pin every field to an allow-list / charset so a hostile
	// admin request cannot inject extra directive lines or corrupt fields.
	name, err := sanitize.ConfLine(strings.TrimSpace(r.FormValue("name")))
	if err != nil {
		fail("name: " + err.Error())
		return
	}
	protocol := strings.TrimSpace(r.FormValue("protocol"))
	if !dpi.IsKnownProtocol(protocol) {
		fail("unknown protocol: " + protocol)
		return
	}
	category, err := sanitize.OneOf(r.FormValue("category"), "it", "ot", "any", "")
	if err != nil {
		fail("category: " + err.Error())
		return
	}
	action, err := sanitize.OneOf(r.FormValue("action"), "forward", "mirror", "drop", "alert")
	if err != nil {
		fail("action: " + err.Error())
		return
	}
	outputPort := strings.TrimSpace(r.FormValue("output_port"))
	if outputPort != "" {
		if outputPort, err = sanitize.Interface(outputPort); err != nil {
			fail("output port: " + err.Error())
			return
		}
		if err := a.checkDataPlane(outputPort); err != nil {
			fail(err.Error())
			return
		}
	}
	if err := a.dpiStore.CreateRule(name, protocol, category, action, outputPort); err != nil {
		fail(err.Error())
		return
	}
	a.dpiStore.WriteDPIConf(filepath.Join(filepath.Dir(a.logPath), "dpi.conf"))
	a.audit(r, "dpi_rule_create", protocol+" → "+action)
	errx.RedirectSuccess(w, r, "/dpi", "DPI rule created")
}
func (a *App) handleDPIDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := errx.ParseID(r, "id")
	if !ok {
		errx.BadRequest(w, "invalid id")
		return
	}
	a.dpiStore.DeleteRule(id)
	a.dpiStore.WriteDPIConf(filepath.Join(filepath.Dir(a.logPath), "dpi.conf"))
	http.Redirect(w, r, "/dpi", http.StatusSeeOther)
}
func (a *App) handleDPIToggle(w http.ResponseWriter, r *http.Request) {
	id, ok := errx.ParseID(r, "id")
	if !ok {
		errx.BadRequest(w, "invalid id")
		return
	}
	a.dpiStore.ToggleRule(id)
	a.dpiStore.WriteDPIConf(filepath.Join(filepath.Dir(a.logPath), "dpi.conf"))
	http.Redirect(w, r, "/dpi", http.StatusSeeOther)
}

// ---------------------------------------------------------------------------
// Packet Masking (#9)
// ---------------------------------------------------------------------------

func (a *App) handleMasking(w http.ResponseWriter, r *http.Request) {
	data := a.baseData(r, "masking")
	data.MaskingRules, _ = a.maskingStore.List()
	data.FlashError = r.URL.Query().Get("error")
	data.FlashSuccess = r.URL.Query().Get("success")
	a.render(w, "masking.html", data)
}
func (a *App) handleMaskingCreate(w http.ResponseWriter, r *http.Request) {
	fail := func(msg string) {
		errx.RedirectErrorMsg(w, r, "/masking", msg)
	}
	// masking.conf is positional CSV (type,method,pattern,replacement,port).
	// Constrain the enum fields and forbid newlines everywhere so no field
	// can inject a new config line. Pattern/replacement may contain commas
	// (regex quantifiers like {2,}) so only CR/LF is rejected there.
	name, err := sanitize.ConfLine(strings.TrimSpace(r.FormValue("name")))
	if err != nil {
		fail("name: " + err.Error())
		return
	}
	typ, err := sanitize.OneOf(r.FormValue("type"), "ip", "mac", "payload", "regex")
	if err != nil {
		fail("type: " + err.Error())
		return
	}
	method, err := sanitize.ConfField(r.FormValue("method"))
	if err != nil {
		fail("method: " + err.Error())
		return
	}
	pattern, err := sanitize.ConfLine(r.FormValue("pattern"))
	if err != nil {
		fail("pattern: " + err.Error())
		return
	}
	replacement, err := sanitize.ConfLine(r.FormValue("replacement"))
	if err != nil {
		fail("replacement: " + err.Error())
		return
	}
	port := strings.TrimSpace(r.FormValue("port"))
	if port != "" {
		if port, err = sanitize.Port(port); err != nil {
			fail("port: " + err.Error())
			return
		}
	}
	if err := a.maskingStore.Create(name, typ, method, pattern, replacement, port); err != nil {
		fail(err.Error())
		return
	}
	a.audit(r, "masking_create", typ+" "+method)
	errx.RedirectSuccess(w, r, "/masking", "Masking rule added")
}
func (a *App) handleMaskingDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := errx.ParseID(r, "id")
	if !ok {
		errx.BadRequest(w, "invalid id")
		return
	}
	a.maskingStore.Delete(id)
	http.Redirect(w, r, "/masking", http.StatusSeeOther)
}
func (a *App) handleMaskingToggle(w http.ResponseWriter, r *http.Request) {
	id, ok := errx.ParseID(r, "id")
	if !ok {
		errx.BadRequest(w, "invalid id")
		return
	}
	a.maskingStore.Toggle(id)
	http.Redirect(w, r, "/masking", http.StatusSeeOther)
}
