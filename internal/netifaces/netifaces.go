// Package netifaces is the single source of truth for which network
// interfaces are "management" (off-limits to the data plane) vs which
// are usable data-plane ports.
//
// Both the UI and the broker.Manager need this distinction:
//
//   - UI filters mgmt iface(s) out of rule/mirror/lb/ssl pickers and
//     refuses any handler input that names one (see App.checkDataPlane).
//   - broker.Manager passes DataPlane() output as argv to the AF_XDP
//     binary at start so XSK sockets bind to every physical NIC except
//     the management ones — gives "ports always ready" UX.
//
// Detection mirrors the AF_XDP C binary's startup guard so what the UI
// allows == what the binary accepts; otherwise the operator would get
// confusing rejected-at-bind surprises.
package netifaces

import (
	"net"
	"os"
	"sort"
	"strings"
)

// DefaultRouteIface returns the interface that owns the default route,
// or "" if none / on non-Linux.
func DefaultRouteIface() string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for i, line := range strings.Split(string(data), "\n") {
		if i == 0 {
			continue // header
		}
		f := strings.Fields(line)
		if len(f) >= 2 && f[1] == "00000000" {
			return f[0]
		}
	}
	return ""
}

// Mgmt returns the deduplicated list of interfaces considered to be
// management — those that own the default route OR carry any
// non-link-local IPv4 address. Result is sorted for stable UI banners.
// Recomputed every call so cable moves / DHCP renews show up live.
func Mgmt() []string {
	set := map[string]bool{}
	if d := DefaultRouteIface(); d != "" {
		set[d] = true
	}
	if ifs, err := net.Interfaces(); err == nil {
		for _, ifc := range ifs {
			if ifc.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, _ := ifc.Addrs()
			for _, a := range addrs {
				ipn, ok := a.(*net.IPNet)
				if !ok {
					continue
				}
				ip := ipn.IP
				if ip.To4() == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
					continue
				}
				set[ifc.Name] = true
				break
			}
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// IsMgmt reports whether name is currently a management interface.
func IsMgmt(name string) bool {
	for _, m := range Mgmt() {
		if m == name {
			return true
		}
	}
	return false
}

// FilterDataPlane returns names with any management iface(s) removed.
// Preserves input order.
func FilterDataPlane(names []string) []string {
	mgmt := map[string]bool{}
	for _, m := range Mgmt() {
		mgmt[m] = true
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if !mgmt[n] {
			out = append(out, n)
		}
	}
	return out
}

// DataPlane enumerates every physical NIC that is NOT a management
// interface — the set that broker.Manager passes to the AF_XDP binary
// at start so XSK sockets bind to every usable port up front.
//
// Excluded: loopback, mgmt iface(s), virtual ifaces (no /sys/class/net/X/device).
func DataPlane() []string {
	mgmt := map[string]bool{}
	for _, m := range Mgmt() {
		mgmt[m] = true
	}

	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if n == "lo" || mgmt[n] {
			continue
		}
		if _, err := os.Stat("/sys/class/net/" + n + "/device"); err != nil {
			continue
		}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
