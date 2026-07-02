package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"packet_broker/internal/broker"
	"packet_broker/internal/dpdkports"
	"packet_broker/internal/logs"
	"packet_broker/internal/netifaces"
	"packet_broker/internal/rules"
	"packet_broker/internal/sanitize"
)

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

// Management-interface helpers — thin wrappers around the shared
// netifaces package so handlers can call `a.MgmtIfaces()` etc. without
// every site needing to import netifaces directly.

func (a *App) MgmtIfaces() []string         { return netifaces.Mgmt() }
func (a *App) IsMgmtIface(name string) bool { return netifaces.IsMgmt(name) }
func (a *App) FilterDataPlane(names []string) []string {
	return netifaces.FilterDataPlane(names)
}

// dataPlaneInterfaces returns the port identifiers the rule pickers offer,
// matching the data-plane mode. libpcap/afxdp → kernel iface names
// (mgmt-excluded). dpdk → DPDK port-ids (mgmt-port-excluded) read from the
// ports manifest the DPDK binary writes at startup (NICs are vfio-bound and
// invisible to the kernel, so there are no names to enumerate).
func (a *App) dataPlaneInterfaces() []string {
	if a.broker.Mode == broker.ModeDPDK {
		return dpdkports.DataPlanePorts(a.rootDir)
	}
	info := a.stats.LinkInfo()
	names := make([]string, 0, len(info))
	for n := range info {
		names = append(names, n)
	}
	sort.Strings(names)
	return a.FilterDataPlane(names)
}

// dataPlaneLabels returns id→label (PCI/MAC) for dpdk ports; nil for kernel
// modes where the name is its own label.
func (a *App) dataPlaneLabels() map[string]string {
	if a.broker.Mode == broker.ModeDPDK {
		return dpdkports.Labels(a.rootDir)
	}
	return nil
}

// checkDataPlane returns a user-friendly error if name is a management
// interface (kernel modes) or management port-id (dpdk). Handlers accepting
// iface form fields call this to reject misconfiguration at the API boundary
// (defense-in-depth — the UI also hides them in pickers).
func (a *App) checkDataPlane(name string) error {
	if name == "" {
		return nil
	}
	if a.broker.Mode == broker.ModeDPDK {
		if dpdkports.IsMgmtPort(name) {
			return fmt.Errorf("port %q is a management port; pick a data-plane port instead", name)
		}
		return nil
	}
	if netifaces.IsMgmt(name) {
		return fmt.Errorf("%q is a management interface; pick a data-plane port instead", name)
	}
	return nil
}

func (a *App) handleRules(w http.ResponseWriter, r *http.Request) {
	ruleList, _ := a.rules.Parse()
	data := a.baseData(r, "rules")
	data.Rules = ruleList
	data.Interfaces = a.dataPlaneInterfaces()
	data.InterfaceLabels = a.dataPlaneLabels()
	a.render(w, "rules.html", data)
}

// parseRuleForm validates and assembles a rules.Rule from the shared add/
// edit form fields. Centralizing it removed the ~70-line validation twin
// that handleAddRule and handleEditRule each carried. Enabled is left zero
// for the caller to set (add defaults it true; edit preserves prior state
// via rules.Update).
func (a *App) parseRuleForm(r *http.Request) (rules.Rule, error) {
	get := func(key, def string) string {
		if v := strings.TrimSpace(r.FormValue(key)); v != "" {
			return v
		}
		return def
	}
	ifIn, err := sanitize.Interface(get("interface_in", ""))
	if err != nil {
		return rules.Rule{}, err
	}
	ifOut, err := sanitize.Interface(get("interface_out", ""))
	if err != nil {
		return rules.Rule{}, err
	}
	if err := a.checkDataPlane(ifIn); err != nil {
		return rules.Rule{}, err
	}
	if err := a.checkDataPlane(ifOut); err != nil {
		return rules.Rule{}, err
	}
	flags, err := sanitize.TCPFlags(get("tcp_flags", "0"))
	if err != nil {
		return rules.Rule{}, err
	}
	dport, err := sanitize.Port(get("dest_port", "0"))
	if err != nil {
		return rules.Rule{}, err
	}
	proto, err := sanitize.Protocol(get("protocol", "0"))
	if err != nil {
		return rules.Rule{}, err
	}
	vlanID, err := sanitize.VLANID(get("vlan_id", "0"))
	if err != nil {
		return rules.Rule{}, err
	}
	vlanAct, err := sanitize.VLANAction(get("vlan_action", "none"))
	if err != nil {
		return rules.Rule{}, err
	}
	srcIP, err := sanitize.IP(get("src_ip", "0"))
	if err != nil {
		return rules.Rule{}, err
	}
	dstIP, err := sanitize.IP(get("dst_ip", "0"))
	if err != nil {
		return rules.Rule{}, err
	}
	srcMAC, err := sanitize.MAC(get("src_mac", "0"))
	if err != nil {
		return rules.Rule{}, err
	}
	dstMAC, err := sanitize.MAC(get("dst_mac", "0"))
	if err != nil {
		return rules.Rule{}, err
	}
	bpf, err := sanitize.BPFFilter(get("bpf_filter", ""))
	if err != nil {
		return rules.Rule{}, err
	}
	return rules.Rule{
		InterfaceIn:  ifIn,
		TCPFlags:     flags,
		DestPort:     dport,
		Protocol:     proto,
		VlanID:       vlanID,
		StringMatch:  sanitize.CSVField(get("string_match", "0")),
		Exclude:      sanitize.CSVField(get("exclude", "0")),
		InterfaceOut: ifOut,
		VlanAction:   vlanAct,
		VlanNewID:    sanitize.CSVField(get("vlan_new_id", "0")),
		Truncate:     sanitize.CSVField(get("truncate", "0")),
		SrcIP:        srcIP,
		DstIP:        dstIP,
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		BPFFilter:    bpf,
	}, nil
}

func (a *App) handleAddRule(w http.ResponseWriter, r *http.Request) {
	newRule, err := a.parseRuleForm(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	newRule.Enabled = true

	// Auto-backup before change
	if a.backups != nil {
		a.backups.AutoBackup()
	}

	if err := a.rules.AddExtended(newRule); err != nil {
		a.logErr("Add rule: " + err.Error())
		http.Error(w, "Add rule failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	a.info("Rule added: " + newRule.InterfaceIn + " → " + newRule.InterfaceOut)
	a.audit(r, "rule_add", newRule.InterfaceIn+" → "+newRule.InterfaceOut)
	http.Redirect(w, r, "/rules", http.StatusSeeOther)
}

func (a *App) handleEditRule(w http.ResponseWriter, r *http.Request) {
	idx, err := strconv.Atoi(r.PathValue("index"))
	if err != nil {
		http.Error(w, "Invalid index", http.StatusBadRequest)
		return
	}

	// Refuse to edit subsystem-managed rules — they must be edited via their
	// owning subsystem (mirror/ssl/lb/dpi) so configs stay in sync.
	ruleList, _ := a.rules.Parse()
	if idx < 0 || idx >= len(ruleList) {
		http.Error(w, "Rule not found", http.StatusNotFound)
		return
	}
	if src := ruleList[idx].Source; src != "" && src != "manual" {
		http.Error(w, "Cannot edit subsystem rule ("+src+"). Edit via the owning page.", http.StatusBadRequest)
		return
	}

	updated, err := a.parseRuleForm(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if a.backups != nil {
		a.backups.AutoBackup()
	}

	if err := a.rules.Update(idx, updated); err != nil {
		a.logErr("Edit rule: " + err.Error())
		http.Error(w, "Edit rule failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	a.info("Rule edited at index " + strconv.Itoa(idx) + ": " + updated.InterfaceIn + " → " + updated.InterfaceOut)
	a.audit(r, "rule_edit", "index="+strconv.Itoa(idx)+" "+updated.InterfaceIn+" → "+updated.InterfaceOut)
	http.Redirect(w, r, "/rules", http.StatusSeeOther)
}

func (a *App) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	idx, err := strconv.Atoi(r.FormValue("index"))
	if err != nil {
		http.Error(w, "Invalid index", http.StatusBadRequest)
		return
	}

	// Before deleting, check if this rule belongs to a subsystem
	// and clean up ALL rules from that subsystem + the subsystem record itself
	ruleList, _ := a.rules.Parse()
	if idx >= 0 && idx < len(ruleList) {
		src := ruleList[idx].Source
		if src != "" && src != "manual" {
			// Remove all rules with same source tag
			a.removeRulesBySource(src)
			// Remove the subsystem record
			a.cleanupSubsystem(src)
			a.info("Subsystem removed via topology: " + src)
			a.audit(r, "rule_delete", "subsystem="+src)
			http.Redirect(w, r, "/rules", http.StatusSeeOther)
			return
		}
	}

	if a.backups != nil {
		a.backups.AutoBackup()
	}
	removed, err := a.rules.Delete(idx)
	if err != nil {
		a.logErr("Delete rule: " + err.Error())
		http.Error(w, "Delete rule failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	a.info("Rule deleted at index " + strconv.Itoa(idx) + ": " + removed)
	a.audit(r, "rule_delete", "index="+strconv.Itoa(idx)+" "+removed)
	http.Redirect(w, r, "/rules", http.StatusSeeOther)
}

func (a *App) handleToggleRule(w http.ResponseWriter, r *http.Request) {
	idx, _ := strconv.Atoi(r.PathValue("index"))
	enabled := r.FormValue("enabled") == "1"
	if err := a.rules.SetEnabled(idx, enabled); err != nil {
		a.logErr("Toggle rule: " + err.Error())
	}
	http.Redirect(w, r, "/rules", http.StatusSeeOther)
}

func (a *App) handleReorderRules(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Order []int `json:"order"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if err := a.rules.Reorder(body.Order); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// ---------------------------------------------------------------------------
// Logs
// ---------------------------------------------------------------------------

func (a *App) handleLogs(w http.ResponseWriter, r *http.Request) {
	perPage := 50
	page := 1
	if v := r.URL.Query().Get("per_page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 10 && n <= 500 {
			perPage = n
		}
	}
	if v := r.URL.Query().Get("page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 10000 {
			page = n
		}
	}
	opsOnly := !a.authStore.IsAdmin(r)
	logPage := logs.ReadPage(a.logPath, page, perPage, opsOnly)
	data := a.baseData(r, "logs")
	data.Page = logPage
	a.render(w, "logs.html", data)
}
