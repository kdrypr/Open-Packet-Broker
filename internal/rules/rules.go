// Package rules manages reading and writing of rules.conf.
//
// Extended CSV format (backward-compatible — missing fields use defaults):
//
//	interface_in, tcp_flags, dest_port, protocol, vlan_id, string_match,
//	exclude, interface_out, enabled, priority, vlan_action, vlan_new_id,
//	truncate, src_ip, dst_ip, src_mac, dst_mac, bpf_filter
package rules

import (
	"bufio"
	"encoding/json"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// ── Types ─────────────────────────────────────────────────────────────────────

// Rule represents one forwarding rule.
type Rule struct {
	Index        int    `json:"index"`
	InterfaceIn  string `json:"interface_in"`
	TCPFlags     string `json:"tcp_flags"`
	DestPort     string `json:"dest_port"`
	Protocol     string `json:"protocol"`
	VlanID       string `json:"vlan_id"`
	StringMatch  string `json:"string_match"`
	Exclude      string `json:"exclude"`
	InterfaceOut string `json:"interface_out"`

	// Feature 2: ordering
	Enabled  bool `json:"enabled"`
	Priority int  `json:"priority"`

	// Feature 6: packet manipulation
	VlanAction string `json:"vlan_action"` // "none", "add", "remove", "change"
	VlanNewID  string `json:"vlan_new_id"` // target VLAN ID for add/change
	Truncate   string `json:"truncate"`    // byte count, "0" = disabled

	// Feature 9: extended filters
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcMAC    string `json:"src_mac"`
	DstMAC    string `json:"dst_mac"`
	BPFFilter string `json:"bpf_filter"`

	// Bandwidth throttling
	RateLimitMbps string `json:"rate_limit_mbps"` // "0" = unlimited
	RateLimitPPS  string `json:"rate_limit_pps"`  // "0" = unlimited

	// Mirroring: extra output ports (comma-separated)
	MirrorPorts string `json:"mirror_ports"`

	// Dedup: key identifier for dedup grouping
	DedupKey string `json:"dedup_key"` // "0" = no dedup

	// Source: which subsystem created this rule
	Source string `json:"source"` // "manual", "mirror", "ssl", "lb", "dpi"
}

// ── Manager ───────────────────────────────────────────────────────────────────

// Manager handles CRUD operations on rules.
// It uses rules_state.json as the authoritative store and writes rules.conf
// as a derived file for the C binary (only enabled rules, 8-field CSV).
type Manager struct {
	Path      string // rules.conf path
	StatePath string // rules_state.json path

	// mu serializes the read-modify-write file mutators below. Without it,
	// concurrent handlers and the healthcheck goroutine (DisableByOutput /
	// EnableByOutput on a 5s ticker) could interleave and corrupt rules.conf.
	mu sync.Mutex
}

// Ensure creates necessary files if they don't exist.
func (m *Manager) Ensure() error {
	for _, p := range []string{m.Path, m.StatePath} {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); os.IsNotExist(err) {
			if err := os.WriteFile(p, []byte{}, 0600); err != nil {
				return err
			}
		}
	}
	return nil
}

// Parse returns all rules sorted by priority.
func (m *Manager) Parse() ([]Rule, error) {
	rules, err := m.loadState()
	if err != nil || len(rules) == 0 {
		// Fallback: read from rules.conf (backward compatibility)
		rules, err = m.parseCSV()
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Priority < rules[j].Priority
	})
	for i := range rules {
		rules[i].Index = i
	}
	return rules, nil
}

// Add appends a new rule.
func (m *Manager) Add(fields [8]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rules, _ := m.loadState()
	if rules == nil {
		rules, _ = m.parseCSV()
	}

	maxPri := 0
	for _, r := range rules {
		if r.Priority >= maxPri {
			maxPri = r.Priority + 1
		}
	}

	rules = append(rules, Rule{
		InterfaceIn:   fields[0],
		TCPFlags:      fields[1],
		DestPort:      fields[2],
		Protocol:      fields[3],
		VlanID:        fields[4],
		StringMatch:   fields[5],
		Exclude:       fields[6],
		InterfaceOut:  fields[7],
		Enabled:       true,
		Priority:      maxPri,
		VlanAction:    "none",
		VlanNewID:     "0",
		Truncate:      "0",
		SrcIP:         "0",
		DstIP:         "0",
		SrcMAC:        "0",
		DstMAC:        "0",
		BPFFilter:     "",
		RateLimitMbps: "0",
		RateLimitPPS:  "0",
		MirrorPorts:   "",
		DedupKey:      "0",
	})

	return m.saveAllLocked(rules)
}

// AddExtended adds a rule with all extended fields.
// NewForwardRule returns a plain input→output forwarding rule with every
// match/manipulation field set to its neutral ("0"/"none") default and the
// given Source tag. The subsystem builders (mirror / ssl / lb) use it so the
// ~12 neutral field assignments live in one place instead of being copy-
// pasted at each call site. Enabled and Priority are assigned by AddExtended.
func NewForwardRule(in, out, source string) Rule {
	return Rule{
		InterfaceIn:  in,
		InterfaceOut: out,
		TCPFlags:     "0",
		DestPort:     "0",
		Protocol:     "0",
		VlanID:       "0",
		StringMatch:  "0",
		Exclude:      "0",
		VlanAction:   "none",
		VlanNewID:    "0",
		Truncate:     "0",
		SrcIP:        "0",
		DstIP:        "0",
		SrcMAC:       "0",
		DstMAC:       "0",
		Source:       source,
	}
}

func (m *Manager) AddExtended(r Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rules, _ := m.loadState()
	if rules == nil {
		rules, _ = m.parseCSV()
	}

	maxPri := 0
	for _, existing := range rules {
		if existing.Priority >= maxPri {
			maxPri = existing.Priority + 1
		}
	}
	r.Priority = maxPri
	if r.VlanAction == "" {
		r.VlanAction = "none"
	}
	if r.Truncate == "" {
		r.Truncate = "0"
	}
	if r.RateLimitMbps == "" {
		r.RateLimitMbps = "0"
	}
	if r.RateLimitPPS == "" {
		r.RateLimitPPS = "0"
	}
	if r.DedupKey == "" {
		r.DedupKey = "0"
	}
	r.Enabled = true
	rules = append(rules, r)
	return m.saveAllLocked(rules)
}

// Update replaces editable fields of the rule at idx, preserving Index,
// Priority, Enabled state, and Source tag (so subsystem-owned rules retain
// their lineage if the caller passes them through Update).
func (m *Manager) Update(idx int, r Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	all, err := m.Parse()
	if err != nil {
		return err
	}
	if idx < 0 || idx >= len(all) {
		return &IndexError{idx, len(all)}
	}
	existing := all[idx]
	r.Index = existing.Index
	r.Priority = existing.Priority
	r.Enabled = existing.Enabled
	r.Source = existing.Source
	if r.VlanAction == "" {
		r.VlanAction = "none"
	}
	if r.Truncate == "" {
		r.Truncate = "0"
	}
	if r.RateLimitMbps == "" {
		r.RateLimitMbps = "0"
	}
	if r.RateLimitPPS == "" {
		r.RateLimitPPS = "0"
	}
	if r.DedupKey == "" {
		r.DedupKey = "0"
	}
	all[idx] = r
	return m.saveAllLocked(all)
}

// Delete removes the rule at the given index.
func (m *Manager) Delete(idx int) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rules, err := m.Parse()
	if err != nil {
		return "", err
	}
	if idx < 0 || idx >= len(rules) {
		return "", &IndexError{idx, len(rules)}
	}
	removed := rules[idx].InterfaceIn + " → " + rules[idx].InterfaceOut
	rules = append(rules[:idx], rules[idx+1:]...)
	return removed, m.saveAllLocked(rules)
}

// SetEnabled toggles the enabled state of a rule.
func (m *Manager) SetEnabled(idx int, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rules, err := m.Parse()
	if err != nil {
		return err
	}
	if idx < 0 || idx >= len(rules) {
		return &IndexError{idx, len(rules)}
	}
	rules[idx].Enabled = enabled
	return m.saveAllLocked(rules)
}

// Reorder sets a new order for rules. newOrder is a slice of current indices
// in the desired order.
func (m *Manager) Reorder(newOrder []int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rules, err := m.Parse()
	if err != nil {
		return err
	}
	if len(newOrder) != len(rules) {
		return &IndexError{len(newOrder), len(rules)}
	}
	reordered := make([]Rule, len(rules))
	for i, oldIdx := range newOrder {
		if oldIdx < 0 || oldIdx >= len(rules) {
			return &IndexError{oldIdx, len(rules)}
		}
		reordered[i] = rules[oldIdx]
		reordered[i].Priority = i
	}
	return m.saveAllLocked(reordered)
}

// ── Persistence ───────────────────────────────────────────────────────────────

func (m *Manager) loadState() ([]Rule, error) {
	if m.StatePath == "" {
		return nil, nil
	}
	data, err := os.ReadFile(m.StatePath)
	if err != nil || len(data) == 0 {
		return nil, err
	}
	var rules []Rule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

// SaveAll persists the full rule list and regenerates rules.conf. Locks the
// manager so external callers are serialized with the mutators.
func (m *Manager) SaveAll(rules []Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.saveAllLocked(rules)
}

// saveAllLocked is SaveAll's body; the caller must already hold m.mu.
func (m *Manager) saveAllLocked(rules []Rule) error {
	// Re-index
	for i := range rules {
		rules[i].Index = i
		rules[i].Priority = i
	}

	// Save state JSON (atomic temp+rename so concurrent readers never see a
	// half-written file).
	if m.StatePath != "" {
		data, err := json.MarshalIndent(rules, "", "  ")
		if err != nil {
			return err
		}
		if err := writeAtomic(m.StatePath, data); err != nil {
			return err
		}
	}

	// Write rules.conf for C binary (enabled rules, full 22-field CSV)
	return m.writeCSV(rules)
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (m *Manager) writeCSV(rules []Rule) error {
	var lines []string
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		fields := []string{
			r.InterfaceIn, r.TCPFlags, r.DestPort, r.Protocol,
			r.VlanID, r.StringMatch, r.Exclude, r.InterfaceOut,
			boolStr(r.Enabled), strconv.Itoa(r.Priority),
			r.VlanAction, r.VlanNewID, r.Truncate,
			r.SrcIP, r.DstIP, r.SrcMAC, r.DstMAC, r.BPFFilter,
			r.RateLimitMbps, r.RateLimitPPS,
			r.MirrorPorts, r.DedupKey,
		}
		lines = append(lines, strings.Join(fields, ","))
	}
	content := strings.Join(lines, "\n")
	if content != "" {
		content += "\n"
	}
	return writeAtomic(m.Path, []byte(content))
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// parseCSV reads the legacy 8-field rules.conf.
func (m *Manager) parseCSV() ([]Rule, error) {
	if err := m.Ensure(); err != nil {
		return nil, err
	}
	f, err := os.Open(m.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var rules []Rule
	idx := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 8 {
			continue
		}
		for i, p := range parts {
			parts[i] = strings.TrimSpace(p)
		}
		rules = append(rules, Rule{
			Index:         idx,
			InterfaceIn:   parts[0],
			TCPFlags:      parts[1],
			DestPort:      parts[2],
			Protocol:      parts[3],
			VlanID:        parts[4],
			StringMatch:   parts[5],
			Exclude:       parts[6],
			InterfaceOut:  parts[7],
			Enabled:       true,
			Priority:      idx,
			VlanAction:    "none",
			VlanNewID:     "0",
			Truncate:      "0",
			SrcIP:         "0",
			DstIP:         "0",
			SrcMAC:        "0",
			DstMAC:        "0",
			BPFFilter:     "",
			RateLimitMbps: "0",
			RateLimitPPS:  "0",
			MirrorPorts:   "",
			DedupKey:      "0",
		})
		idx++
	}
	return rules, scanner.Err()
}

// DisableByOutput disables all rules forwarding to the given port.
func (m *Manager) DisableByOutput(port string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rules, err := m.Parse()
	if err != nil {
		return 0, err
	}
	count := 0
	for i := range rules {
		if rules[i].InterfaceOut == port && rules[i].Enabled {
			rules[i].Enabled = false
			count++
		}
	}
	if count > 0 {
		m.saveAllLocked(rules)
	}
	return count, nil
}

// EnableByOutput re-enables all rules forwarding to the given port.
func (m *Manager) EnableByOutput(port string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rules, err := m.Parse()
	if err != nil {
		return 0, err
	}
	count := 0
	for i := range rules {
		if rules[i].InterfaceOut == port && !rules[i].Enabled {
			rules[i].Enabled = true
			count++
		}
	}
	if count > 0 {
		m.saveAllLocked(rules)
	}
	return count, nil
}

// ── Error types ───────────────────────────────────────────────────────────────

// IndexError is returned when a rule index is out of range.
type IndexError struct {
	Got int
	Max int
}

func (e *IndexError) Error() string {
	return "rule index " + strconv.Itoa(e.Got) + " out of range (max " + strconv.Itoa(e.Max-1) + ")"
}
