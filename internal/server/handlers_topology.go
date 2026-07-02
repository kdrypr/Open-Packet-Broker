package server

import (
	"net/http"
	"strconv"
	"strings"

	"packet_broker/internal/errx"
	"packet_broker/internal/rules"
)

// ---------------------------------------------------------------------------
// Load Balancing (Feature 5)
// ---------------------------------------------------------------------------

func (a *App) handleLoadBalance(w http.ResponseWriter, r *http.Request) {
	data := a.baseData(r, "loadbalance")
	data.PortGroups, _ = a.portGroups.List()
	data.FlashError = r.URL.Query().Get("error")
	data.FlashSuccess = r.URL.Query().Get("success")
	a.render(w, "loadbalance.html", data)
}

func (a *App) handleLoadBalanceCreate(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	mode := r.FormValue("mode")
	inputs := strings.Split(r.FormValue("input_ports"), ",")
	outputs := strings.Split(r.FormValue("output_ports"), ",")

	// Clean
	var cleanIn, cleanOut []string
	for _, p := range inputs {
		if t := strings.TrimSpace(p); t != "" {
			cleanIn = append(cleanIn, t)
		}
	}
	for _, p := range outputs {
		if t := strings.TrimSpace(p); t != "" {
			cleanOut = append(cleanOut, t)
		}
	}

	// Refuse any management iface — data-plane only
	for _, p := range append(append([]string{}, cleanIn...), cleanOut...) {
		if err := a.checkDataPlane(p); err != nil {
			errx.RedirectError(w, r, "/load-balance", err)
			return
		}
	}

	if _, err := a.portGroups.Create(name, mode, cleanIn, cleanOut); err != nil {
		errx.RedirectError(w, r, "/load-balance", err)
		return
	}
	// Generate rules for each input→output pair
	for _, in := range cleanIn {
		for _, out := range cleanOut {
			a.rules.AddExtended(rules.NewForwardRule(in, out, "lb:"+name))
		}
	}
	a.info("Port group created: " + name)
	errx.RedirectSuccess(w, r, "/rules", "LB group '"+name+"' created")
}

func (a *App) handleLoadBalanceDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := errx.ParseID(r, "id")
	if !ok {
		errx.BadRequest(w, "invalid id")
		return
	}
	groups, _ := a.portGroups.List()
	for _, g := range groups {
		if g.ID == id {
			a.removeRulesBySource("lb:" + g.Name)
			break
		}
	}
	a.portGroups.Delete(id)
	http.Redirect(w, r, "/load-balance", http.StatusSeeOther)
}

// ---------------------------------------------------------------------------
// Mirror (F6)
// ---------------------------------------------------------------------------

func (a *App) handleMirror(w http.ResponseWriter, r *http.Request) {
	data := a.baseData(r, "mirror")
	data.MirrorSessions, _ = a.mirrors.List()
	data.FlashError = r.URL.Query().Get("error")
	data.FlashSuccess = r.URL.Query().Get("success")
	a.render(w, "mirror.html", data)
}
func (a *App) handleMirrorCreate(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	src := strings.TrimSpace(r.FormValue("src_port"))
	dsts := strings.Split(r.FormValue("dst_ports"), ",")
	var clean []string
	for _, d := range dsts {
		if t := strings.TrimSpace(d); t != "" {
			clean = append(clean, t)
		}
	}

	// Refuse mgmt iface anywhere
	if err := a.checkDataPlane(src); err != nil {
		errx.RedirectError(w, r, "/mirror", err)
		return
	}
	for _, d := range clean {
		if err := a.checkDataPlane(d); err != nil {
			errx.RedirectError(w, r, "/mirror", err)
			return
		}
	}

	// Remove any existing mirror with same name (prevent duplicates)
	existing, _ := a.mirrors.List()
	for _, s := range existing {
		if s.Name == name {
			a.mirrors.Delete(s.ID)
		}
	}
	a.removeRulesBySource("mirror:" + name)

	if _, err := a.mirrors.Create(name, src, clean); err != nil {
		errx.RedirectError(w, r, "/mirror", err)
		return
	}
	for _, dst := range clean {
		a.rules.AddExtended(rules.NewForwardRule(src, dst, "mirror:"+name))
	}
	a.info("Mirror created: " + name)
	errx.RedirectSuccess(w, r, "/rules", "Mirror '"+name+"' created")
}
func (a *App) handleMirrorDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := errx.ParseID(r, "id")
	if !ok {
		errx.BadRequest(w, "invalid id")
		return
	}
	// Remove associated rules from rules_state
	sessions, _ := a.mirrors.List()
	for _, s := range sessions {
		if s.ID == id {
			a.removeRulesBySource("mirror:" + s.Name)
			break
		}
	}
	a.mirrors.Delete(id)
	http.Redirect(w, r, "/mirror", http.StatusSeeOther)
}
func (a *App) handleMirrorToggle(w http.ResponseWriter, r *http.Request) {
	id, ok := errx.ParseID(r, "id")
	if !ok {
		errx.BadRequest(w, "invalid id")
		return
	}
	a.mirrors.Toggle(id)
	http.Redirect(w, r, "/mirror", http.StatusSeeOther)
}

// ---------------------------------------------------------------------------
// Throttle (F7)
// ---------------------------------------------------------------------------

func (a *App) handleThrottle(w http.ResponseWriter, r *http.Request) {
	data := a.baseData(r, "throttle")
	data.ThrottleConfigs, _ = a.throttles.List()
	data.FlashError = r.URL.Query().Get("error")
	data.FlashSuccess = r.URL.Query().Get("success")
	a.render(w, "throttle.html", data)
}
func (a *App) handleThrottleCreate(w http.ResponseWriter, r *http.Request) {
	port := strings.TrimSpace(r.FormValue("port"))
	if err := a.checkDataPlane(port); err != nil {
		errx.RedirectError(w, r, "/throttle", err)
		return
	}
	mbps, _ := strconv.Atoi(r.FormValue("max_mbps"))
	pps, _ := strconv.Atoi(r.FormValue("max_pps"))
	if _, err := a.throttles.Create(port, mbps, pps); err != nil {
		errx.RedirectError(w, r, "/throttle", err)
		return
	}
	errx.RedirectSuccess(w, r, "/throttle", "Rate limit added")
}
func (a *App) handleThrottleDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := errx.ParseID(r, "id")
	if !ok {
		errx.BadRequest(w, "invalid id")
		return
	}
	a.throttles.Delete(id)
	http.Redirect(w, r, "/throttle", http.StatusSeeOther)
}
func (a *App) handleThrottleToggle(w http.ResponseWriter, r *http.Request) {
	id, ok := errx.ParseID(r, "id")
	if !ok {
		errx.BadRequest(w, "invalid id")
		return
	}
	a.throttles.Toggle(id)
	http.Redirect(w, r, "/throttle", http.StatusSeeOther)
}

// ---------------------------------------------------------------------------
// SSL Decrypt (F2)
// ---------------------------------------------------------------------------

func (a *App) handleSSLDecrypt(w http.ResponseWriter, r *http.Request) {
	data := a.baseData(r, "ssldecrypt")
	data.SSLChains, _ = a.sslChains.List()
	data.FlashError = r.URL.Query().Get("error")
	data.FlashSuccess = r.URL.Query().Get("success")
	a.render(w, "ssldecrypt.html", data)
}
func (a *App) handleSSLDecryptCreate(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	enc := strings.TrimSpace(r.FormValue("encrypted_port"))
	tool := strings.TrimSpace(r.FormValue("decrypt_tool_port"))
	reinj := strings.TrimSpace(r.FormValue("reinject_port"))
	filter := strings.TrimSpace(r.FormValue("filter"))
	for _, p := range []string{enc, tool, reinj} {
		if err := a.checkDataPlane(p); err != nil {
			errx.RedirectError(w, r, "/ssl-decrypt", err)
			return
		}
	}
	if _, err := a.sslChains.Create(name, enc, tool, reinj, filter); err != nil {
		errx.RedirectError(w, r, "/ssl-decrypt", err)
		return
	}
	// Rule 1: encrypted → tool (carries the optional BPF pre-filter)
	encRule := rules.NewForwardRule(enc, tool, "ssl:"+name)
	encRule.BPFFilter = filter
	a.rules.AddExtended(encRule)
	// Rule 2: tool → reinject
	a.rules.AddExtended(rules.NewForwardRule(tool, reinj, "ssl:"+name))
	a.info("SSL chain created: " + name)
	errx.RedirectSuccess(w, r, "/rules", "SSL chain '"+name+"' created")
}
func (a *App) handleSSLDecryptDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := errx.ParseID(r, "id")
	if !ok {
		errx.BadRequest(w, "invalid id")
		return
	}
	sessions, _ := a.sslChains.List()
	for _, s := range sessions {
		if s.ID == id {
			a.removeRulesBySource("ssl:" + s.Name)
			break
		}
	}
	a.sslChains.Delete(id)
	http.Redirect(w, r, "/ssl-decrypt", http.StatusSeeOther)
}
func (a *App) handleSSLDecryptToggle(w http.ResponseWriter, r *http.Request) {
	id, ok := errx.ParseID(r, "id")
	if !ok {
		errx.BadRequest(w, "invalid id")
		return
	}
	a.sslChains.Toggle(id)
	http.Redirect(w, r, "/ssl-decrypt", http.StatusSeeOther)
}

// ---------------------------------------------------------------------------
// Dedup (F3)
// ---------------------------------------------------------------------------

func (a *App) handleDedup(w http.ResponseWriter, r *http.Request) {
	data := a.baseData(r, "dedup")
	data.DedupConfigs, _ = a.dedupStore.List()
	data.FlashError = r.URL.Query().Get("error")
	data.FlashSuccess = r.URL.Query().Get("success")
	a.render(w, "dedup.html", data)
}
func (a *App) handleDedupCreate(w http.ResponseWriter, r *http.Request) {
	port := strings.TrimSpace(r.FormValue("port"))
	// Empty port = global dedup (allowed); non-empty must be data-plane
	if err := a.checkDataPlane(port); err != nil {
		errx.RedirectError(w, r, "/dedup", err)
		return
	}
	wms, _ := strconv.Atoi(r.FormValue("window_ms"))
	hb, _ := strconv.Atoi(r.FormValue("hash_bytes"))
	if _, err := a.dedupStore.Create(port, wms, hb); err != nil {
		errx.RedirectError(w, r, "/dedup", err)
		return
	}
	errx.RedirectSuccess(w, r, "/dedup", "Dedup rule added")
}
func (a *App) handleDedupDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := errx.ParseID(r, "id")
	if !ok {
		errx.BadRequest(w, "invalid id")
		return
	}
	a.dedupStore.Delete(id)
	http.Redirect(w, r, "/dedup", http.StatusSeeOther)
}
func (a *App) handleDedupToggle(w http.ResponseWriter, r *http.Request) {
	id, ok := errx.ParseID(r, "id")
	if !ok {
		errx.BadRequest(w, "invalid id")
		return
	}
	a.dedupStore.Toggle(id)
	http.Redirect(w, r, "/dedup", http.StatusSeeOther)
}

// ---------------------------------------------------------------------------
// Subsystem rule helpers
// ---------------------------------------------------------------------------

// removeRulesBySource deletes all rules with a matching Source tag.
// cleanupSubsystem deletes the mirror/SSL/LB record that generated rules with this source tag.
func (a *App) cleanupSubsystem(source string) {
	parts := strings.SplitN(source, ":", 2)
	if len(parts) != 2 {
		return
	}
	typ, name := parts[0], parts[1]

	switch typ {
	case "mirror":
		sessions, _ := a.mirrors.List()
		for _, s := range sessions {
			if s.Name == name {
				a.mirrors.Delete(s.ID)
			}
		}
	case "ssl":
		chains, _ := a.sslChains.List()
		for _, c := range chains {
			if c.Name == name {
				a.sslChains.Delete(c.ID)
			}
		}
	case "lb":
		groups, _ := a.portGroups.List()
		for _, g := range groups {
			if g.Name == name {
				a.portGroups.Delete(g.ID)
			}
		}
	}
}

func (a *App) removeRulesBySource(source string) {
	ruleList, err := a.rules.Parse()
	if err != nil {
		return
	}
	var keep []rules.Rule
	for _, r := range ruleList {
		if r.Source != source {
			keep = append(keep, r)
		}
	}
	if len(keep) != len(ruleList) {
		a.rules.SaveAll(keep)
	}
}
