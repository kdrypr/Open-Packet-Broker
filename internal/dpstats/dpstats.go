// Package dpstats reads per-iface counters written by the AF_XDP C binary.
//
// The C binary atomically replaces /opt/packet-broker/packet_broker_afxdp.stats.json
// every STATS_INTERVAL (5s). This package exposes a thin reader that returns
// the latest snapshot — UI code merges these counters into the regular stats
// view when BROKER_MODE=afxdp (kernel /proc/net/dev counters don't reflect
// AF_XDP traffic because the packets are XDP_REDIRECTed before reaching the
// stack on TX, and the kernel stack is bypassed entirely on RX).
package dpstats

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// IfaceStats holds counters for a single data-plane interface.
type IfaceStats struct {
	RxPkts  uint64 `json:"rx_pkts"`
	RxBytes uint64 `json:"rx_bytes"`
	TxPkts  uint64 `json:"tx_pkts"`
	TxBytes uint64 `json:"tx_bytes"`
	RxDrop  uint64 `json:"rx_drop"`
	TxDrop  uint64 `json:"tx_drop"`
}

// Snapshot is the top-level JSON written by the C binary.
type Snapshot struct {
	Mode   string                `json:"mode"`
	TS     int64                 `json:"ts"`
	Ifaces map[string]IfaceStats `json:"ifaces"`
}

// Reader caches the last successfully-parsed snapshot.
type Reader struct {
	path string
	mu   sync.RWMutex
	last Snapshot
	when time.Time
}

// New returns a reader pinned to <rootDir>/packet_broker_afxdp.stats.json.
func New(rootDir string) *Reader {
	return &Reader{path: filepath.Join(rootDir, "packet_broker_afxdp.stats.json")}
}

// Refresh re-reads the file if it has changed since last load. Cheap on
// no-change (just stat). Returns the current snapshot.
func (r *Reader) Refresh() Snapshot {
	st, err := os.Stat(r.path)
	if err != nil {
		return Snapshot{}
	}
	r.mu.RLock()
	if st.ModTime().Equal(r.when) {
		s := r.last
		r.mu.RUnlock()
		return s
	}
	r.mu.RUnlock()

	data, err := os.ReadFile(r.path)
	if err != nil {
		return Snapshot{}
	}
	var s Snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return Snapshot{}
	}
	r.mu.Lock()
	r.last = s
	r.when = st.ModTime()
	r.mu.Unlock()
	return s
}
