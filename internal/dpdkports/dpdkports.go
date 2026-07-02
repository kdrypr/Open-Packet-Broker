// Package dpdkports bridges the DPDK port-id world and the UI's name-based
// interface model.
//
// In DPDK mode the data-plane NICs are bound to a DPDK driver (vfio-pci) and
// therefore disappear from the kernel — netifaces/netstats (which read /sys)
// can't see them, and rules address ports by numeric id. At startup the DPDK
// binary writes a manifest (id → PCI → MAC) to <root>/packet_broker_dpdk.ports.json;
// this package reads it so the UI can offer the ports (labelled with their PCI
// address / MAC) in rule pickers and exclude the management port.
package dpdkports

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ManifestFile is the per-startup port manifest the DPDK binary writes.
const ManifestFile = "packet_broker_dpdk.ports.json"

// Port describes one DPDK ethdev port.
type Port struct {
	ID  int    `json:"id"`
	PCI string `json:"pci"`
	MAC string `json:"mac"`
}

// Label is a human-friendly picker label, e.g. "port 1 · 0000:02:00.0".
func (p Port) Label() string {
	l := "port " + strconv.Itoa(p.ID)
	if p.PCI != "" {
		l += " · " + p.PCI
	} else if p.MAC != "" {
		l += " · " + p.MAC
	}
	return l
}

type manifest struct {
	Ports []Port `json:"ports"`
}

// Read returns the ports from the manifest in rootDir. If the manifest is
// absent (the data plane hasn't started yet) it falls back to a synthetic list
// of 0..n-1 where n comes from the PB_DPDK_NUM_PORTS env (so the operator can
// author rules before the first start), or an empty slice when neither exists.
func Read(rootDir string) []Port {
	data, err := os.ReadFile(filepath.Join(rootDir, ManifestFile))
	if err == nil {
		var m manifest
		if json.Unmarshal(data, &m) == nil && len(m.Ports) > 0 {
			return m.Ports
		}
	}
	if n, err := strconv.Atoi(strings.TrimSpace(os.Getenv("PB_DPDK_NUM_PORTS"))); err == nil && n > 0 {
		out := make([]Port, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, Port{ID: i})
		}
		return out
	}
	return nil
}

// MgmtPortSet parses PB_DPDK_MGMT_PORTS (CSV of ids) — the ports rules may not
// bind. Mirrors the C binary's guard so the UI excludes the same ones.
func MgmtPortSet() map[int]bool {
	set := map[int]bool{}
	for _, tok := range strings.Split(os.Getenv("PB_DPDK_MGMT_PORTS"), ",") {
		if id, err := strconv.Atoi(strings.TrimSpace(tok)); err == nil {
			set[id] = true
		}
	}
	return set
}

// DataPlanePorts returns the non-management ports the UI should offer in rule
// pickers, as their string ids (matching the rules.conf interface fields).
func DataPlanePorts(rootDir string) []string {
	mgmt := MgmtPortSet()
	var out []string
	for _, p := range Read(rootDir) {
		if mgmt[p.ID] {
			continue
		}
		out = append(out, strconv.Itoa(p.ID))
	}
	return out
}

// Labels returns id→label for the non-management ports, for richer pickers.
func Labels(rootDir string) map[string]string {
	mgmt := MgmtPortSet()
	out := map[string]string{}
	for _, p := range Read(rootDir) {
		if mgmt[p.ID] {
			continue
		}
		out[strconv.Itoa(p.ID)] = p.Label()
	}
	return out
}

// IsMgmtPort reports whether the given port-id string is a management port.
func IsMgmtPort(id string) bool {
	n, err := strconv.Atoi(strings.TrimSpace(id))
	if err != nil {
		return false
	}
	return MgmtPortSet()[n]
}
