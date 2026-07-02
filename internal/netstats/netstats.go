// Package netstats reads per-interface network statistics and link status
// from Linux sysfs/procfs. Degrades gracefully on non-Linux (returns zeros).
package netstats

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ── Types ─────────────────────────────────────────────────────────────────────

// PortStats holds raw counters for one interface snapshot.
type PortStats struct {
	RxPackets uint64 `json:"rx_packets"`
	TxPackets uint64 `json:"tx_packets"`
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxDropped uint64 `json:"rx_dropped"`
	TxDropped uint64 `json:"tx_dropped"`
	RxErrors  uint64 `json:"rx_errors"`
	TxErrors  uint64 `json:"tx_errors"`
}

// PortRate holds per-second rates computed from two snapshots.
type PortRate struct {
	RxPPS   float64 `json:"rx_pps"` // packets/sec
	TxPPS   float64 `json:"tx_pps"`
	RxBPS   float64 `json:"rx_bps"` // bytes/sec
	TxBPS   float64 `json:"tx_bps"`
	RxDrops float64 `json:"rx_drops"` // drops/sec
	TxDrops float64 `json:"tx_drops"`
}

// PortInfo holds link-layer status.
type PortInfo struct {
	Name      string `json:"name"`
	OperState string `json:"oper_state"` // "up", "down", "unknown"
	Speed     int    `json:"speed"`      // Mbps, 0 if unknown
	Duplex    string `json:"duplex"`     // "full", "half", "unknown"
	MTU       int    `json:"mtu"`
}

// Snapshot is a point-in-time set of stats for all interfaces.
type Snapshot struct {
	Time  time.Time
	Stats map[string]PortStats
}

// SparkPoint is one data point for sparkline charts.
type SparkPoint struct {
	T     int64   `json:"t"` // unix timestamp
	RxBPS float64 `json:"rx"`
	TxBPS float64 `json:"tx"`
}

// ── Collector ─────────────────────────────────────────────────────────────────

const (
	sparkLen = 60 // 60 data points for sparklines
)

// Collector polls network statistics at a fixed interval and maintains
// rate calculations + sparkline ring buffers.
type Collector struct {
	mu        sync.RWMutex
	interval  time.Duration
	prev      Snapshot
	curr      Snapshot
	rates     map[string]PortRate
	portInfo  map[string]PortInfo
	sparkline map[string][]SparkPoint // ring buffer per interface
	stopCh    chan struct{}
}

// NewCollector creates and starts a background stats collector.
func NewCollector(interval time.Duration) *Collector {
	c := &Collector{
		interval:  interval,
		rates:     make(map[string]PortRate),
		portInfo:  make(map[string]PortInfo),
		sparkline: make(map[string][]SparkPoint),
		stopCh:    make(chan struct{}),
	}
	// Initial read
	c.curr = Snapshot{Time: time.Now(), Stats: ReadAll()}
	c.refreshPortInfo()
	go c.loop()
	return c
}

func (c *Collector) loop() {
	tick := time.NewTicker(c.interval)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			c.tick()
		case <-c.stopCh:
			return
		}
	}
}

func (c *Collector) tick() {
	now := time.Now()
	stats := ReadAll()

	c.mu.Lock()
	defer c.mu.Unlock()

	c.prev = c.curr
	c.curr = Snapshot{Time: now, Stats: stats}

	dt := c.curr.Time.Sub(c.prev.Time).Seconds()
	if dt <= 0 {
		return
	}

	// Compute rates
	for iface, cur := range c.curr.Stats {
		prev, ok := c.prev.Stats[iface]
		if !ok {
			continue
		}
		r := PortRate{
			RxPPS:   delta(cur.RxPackets, prev.RxPackets, dt),
			TxPPS:   delta(cur.TxPackets, prev.TxPackets, dt),
			RxBPS:   delta(cur.RxBytes, prev.RxBytes, dt),
			TxBPS:   delta(cur.TxBytes, prev.TxBytes, dt),
			RxDrops: delta(cur.RxDropped, prev.RxDropped, dt),
			TxDrops: delta(cur.TxDropped, prev.TxDropped, dt),
		}
		c.rates[iface] = r

		// Append to sparkline ring
		sp := c.sparkline[iface]
		sp = append(sp, SparkPoint{T: now.Unix(), RxBPS: r.RxBPS, TxBPS: r.TxBPS})
		if len(sp) > sparkLen {
			sp = sp[len(sp)-sparkLen:]
		}
		c.sparkline[iface] = sp
	}

	// Refresh port info (link state) every tick
	c.refreshPortInfoLocked()
}

// Stop halts the collector goroutine.
func (c *Collector) Stop() { close(c.stopCh) }

// ── Public accessors ──────────────────────────────────────────────────────────

// Rates returns the latest per-second rates for all interfaces.
func (c *Collector) Rates() map[string]PortRate {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]PortRate, len(c.rates))
	for k, v := range c.rates {
		out[k] = v
	}
	return out
}

// Stats returns the latest raw counters.
func (c *Collector) Stats() map[string]PortStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]PortStats, len(c.curr.Stats))
	for k, v := range c.curr.Stats {
		out[k] = v
	}
	return out
}

// LinkInfo returns port link/speed/duplex info.
func (c *Collector) LinkInfo() map[string]PortInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]PortInfo, len(c.portInfo))
	for k, v := range c.portInfo {
		out[k] = v
	}
	return out
}

// Sparkline returns the sparkline ring buffer for an interface.
func (c *Collector) Sparkline(iface string) []SparkPoint {
	c.mu.RLock()
	defer c.mu.RUnlock()
	sp := c.sparkline[iface]
	out := make([]SparkPoint, len(sp))
	copy(out, sp)
	return out
}

// AllSparklines returns sparklines for all interfaces.
func (c *Collector) AllSparklines() map[string][]SparkPoint {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string][]SparkPoint, len(c.sparkline))
	for k, v := range c.sparkline {
		cp := make([]SparkPoint, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out
}

// ── Linux readers ─────────────────────────────────────────────────────────────

// ReadAll parses /proc/net/dev for all interface statistics.
func ReadAll() map[string]PortStats {
	if runtime.GOOS != "linux" {
		return map[string]PortStats{}
	}
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return map[string]PortStats{}
	}
	defer f.Close()

	result := make(map[string]PortStats)
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		if lineNo <= 2 {
			continue // skip header lines
		}
		line := scanner.Text()
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		iface := strings.TrimSpace(line[:idx])
		if iface == "lo" {
			continue
		}
		fields := strings.Fields(line[idx+1:])
		if len(fields) < 16 {
			continue
		}
		result[iface] = PortStats{
			RxBytes:   parseU64(fields[0]),
			RxPackets: parseU64(fields[1]),
			RxErrors:  parseU64(fields[2]),
			RxDropped: parseU64(fields[3]),
			TxBytes:   parseU64(fields[8]),
			TxPackets: parseU64(fields[9]),
			TxErrors:  parseU64(fields[10]),
			TxDropped: parseU64(fields[11]),
		}
	}
	return result
}

func (c *Collector) refreshPortInfo() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refreshPortInfoLocked()
}

func (c *Collector) refreshPortInfoLocked() {
	if runtime.GOOS != "linux" {
		return
	}
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if name == "lo" {
			continue
		}
		base := filepath.Join("/sys/class/net", name)
		c.portInfo[name] = PortInfo{
			Name:      name,
			OperState: readSysFile(filepath.Join(base, "operstate"), "unknown"),
			Speed:     readSysInt(filepath.Join(base, "speed"), 0),
			Duplex:    readSysFile(filepath.Join(base, "duplex"), "unknown"),
			MTU:       readSysInt(filepath.Join(base, "mtu"), 1500),
		}
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func delta(cur, prev uint64, dt float64) float64 {
	if cur < prev {
		return 0 // counter wrap or reset
	}
	return float64(cur-prev) / dt
}

func parseU64(s string) uint64 {
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}

func readSysFile(path, fallback string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return fallback
	}
	return strings.TrimSpace(string(data))
}

func readSysInt(path string, fallback int) int {
	s := readSysFile(path, "")
	if s == "" {
		return fallback
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return fallback
	}
	return v
}
