package dpdkports

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadManifestAndMgmtExclusion(t *testing.T) {
	dir := t.TempDir()
	manifest := `{"ports":[
		{"id":0,"pci":"0000:01:00.0","mac":"aa:bb:cc:00:00:00"},
		{"id":1,"pci":"0000:02:00.0","mac":"aa:bb:cc:00:00:01"},
		{"id":2,"pci":"0000:03:00.0","mac":"aa:bb:cc:00:00:02"}]}`
	if err := os.WriteFile(filepath.Join(dir, ManifestFile), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PB_DPDK_MGMT_PORTS", "0") // port 0 is management

	ports := DataPlanePorts(dir)
	if len(ports) != 2 || ports[0] != "1" || ports[1] != "2" {
		t.Fatalf("expected [1 2] (mgmt port 0 excluded), got %v", ports)
	}
	if !IsMgmtPort("0") || IsMgmtPort("1") {
		t.Fatal("IsMgmtPort gate wrong")
	}
	labels := Labels(dir)
	if labels["1"] != "port 1 · 0000:02:00.0" {
		t.Fatalf("unexpected label: %q", labels["1"])
	}
	if _, ok := labels["0"]; ok {
		t.Fatal("mgmt port must not appear in labels")
	}
}

func TestFallbackNumPortsWhenNoManifest(t *testing.T) {
	dir := t.TempDir() // no manifest
	t.Setenv("PB_DPDK_NUM_PORTS", "4")
	t.Setenv("PB_DPDK_MGMT_PORTS", "3")
	ports := DataPlanePorts(dir)
	// 0,1,2 offered; 3 is mgmt
	if len(ports) != 3 {
		t.Fatalf("expected 3 ports (0..2, mgmt 3 excluded), got %v", ports)
	}
}

func TestEmptyWhenNothingConfigured(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PB_DPDK_NUM_PORTS", "")
	t.Setenv("PB_DPDK_MGMT_PORTS", "")
	if got := DataPlanePorts(dir); len(got) != 0 {
		t.Fatalf("expected empty, got %v", got)
	}
}
