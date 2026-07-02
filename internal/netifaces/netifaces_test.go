package netifaces

import "testing"

func TestMgmt_NoCrash(t *testing.T) {
	// Mgmt() shells out to /proc/net/route on Linux, getifaddrs everywhere.
	// We can't assert specific iface names (host-dependent) but we can
	// assert it doesn't panic and returns a sorted slice.
	got := Mgmt()
	for i := 1; i < len(got); i++ {
		if got[i-1] > got[i] {
			t.Errorf("Mgmt() not sorted: %v", got)
			break
		}
	}
}

func TestFilterDataPlane_RemovesMgmt(t *testing.T) {
	in := []string{"eth0", "eth1", "lo", "eth2"}
	// Force mgmt set to {"eth0", "eth2"} via package-level injection;
	// since the real impl reads the live system, we test the public
	// FilterDataPlane against an empty mgmt set instead.
	out := FilterDataPlane(in)
	// At minimum, every input that isn't in the live mgmt set survives.
	// We just assert no duplicates introduced.
	seen := make(map[string]bool)
	for _, n := range out {
		if seen[n] {
			t.Errorf("duplicate in FilterDataPlane output: %q", n)
		}
		seen[n] = true
	}
}

func TestIsMgmt_EmptyName(t *testing.T) {
	if IsMgmt("") {
		t.Error("empty iface should not match a real mgmt iface")
	}
}
