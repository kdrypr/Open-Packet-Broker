// Package sysinfo reads system metrics (CPU, memory, uptime) from Linux
// procfs. Degrades gracefully on non-Linux (returns zeros).
package sysinfo

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ── Types ─────────────────────────────────────────────────────────────────────

// SystemSnapshot is a point-in-time reading of system metrics.
type SystemSnapshot struct {
	Uptime     time.Duration `json:"-"`
	UptimeStr  string        `json:"uptime"`
	CPUPercent float64       `json:"cpu_percent"`
	MemTotal   uint64        `json:"mem_total"`
	MemUsed    uint64        `json:"mem_used"`
	MemPercent float64       `json:"mem_percent"`
}

// TrafficPoint is one data point for the 24h traffic chart.
type TrafficPoint struct {
	T  int64   `json:"t"`  // unix timestamp
	Rx float64 `json:"rx"` // total RX bytes/sec across all interfaces
	Tx float64 `json:"tx"` // total TX bytes/sec
}

// cpuSample holds raw CPU jiffies from /proc/stat.
type cpuSample struct {
	idle  uint64
	total uint64
}

// ── Collector ─────────────────────────────────────────────────────────────────

const (
	trafficHistLen = 1440 // 24h at 1-minute granularity
)

// Collector runs a background goroutine to sample system metrics.
type Collector struct {
	mu          sync.RWMutex
	current     SystemSnapshot
	prevCPU     cpuSample
	trafficHist []TrafficPoint
	getRates    func() map[string]float64 // injected: returns per-iface RX+TX bps
	stopCh      chan struct{}
}

// NewCollector creates and starts a system metrics collector.
// getRates should return a map[iface]totalBPS from the netstats collector.
func NewCollector(getRates func() map[string]float64) *Collector {
	c := &Collector{
		trafficHist: make([]TrafficPoint, 0, trafficHistLen),
		getRates:    getRates,
		stopCh:      make(chan struct{}),
	}
	c.prevCPU = readCPU()
	c.sample()
	go c.loop()
	return c
}

func (c *Collector) loop() {
	fast := time.NewTicker(2 * time.Second)  // CPU/memory updates
	slow := time.NewTicker(60 * time.Second) // traffic history
	defer fast.Stop()
	defer slow.Stop()
	for {
		select {
		case <-fast.C:
			c.sample()
		case <-slow.C:
			c.recordTraffic()
		case <-c.stopCh:
			return
		}
	}
}

func (c *Collector) sample() {
	snap := SystemSnapshot{}

	// Uptime
	snap.Uptime = readUptime()
	snap.UptimeStr = fmtDuration(snap.Uptime)

	// CPU
	cur := readCPU()
	c.mu.Lock()
	prev := c.prevCPU
	c.prevCPU = cur
	c.mu.Unlock()

	totalDelta := cur.total - prev.total
	idleDelta := cur.idle - prev.idle
	if totalDelta > 0 {
		snap.CPUPercent = float64(totalDelta-idleDelta) / float64(totalDelta) * 100
	}

	// Memory
	snap.MemTotal, snap.MemUsed = readMemory()
	if snap.MemTotal > 0 {
		snap.MemPercent = float64(snap.MemUsed) / float64(snap.MemTotal) * 100
	}

	c.mu.Lock()
	c.current = snap
	c.mu.Unlock()
}

func (c *Collector) recordTraffic() {
	if c.getRates == nil {
		return
	}
	rates := c.getRates()
	var totalRx, totalTx float64
	for _, bps := range rates {
		totalRx += bps // simplified: getRates returns rx+tx combined per iface
	}
	_ = totalTx // will be separated when wired up

	c.mu.Lock()
	c.trafficHist = append(c.trafficHist, TrafficPoint{
		T: time.Now().Unix(), Rx: totalRx, Tx: totalTx,
	})
	if len(c.trafficHist) > trafficHistLen {
		c.trafficHist = c.trafficHist[len(c.trafficHist)-trafficHistLen:]
	}
	c.mu.Unlock()
}

// Stop halts the collector.
func (c *Collector) Stop() { close(c.stopCh) }

// ── Public accessors ──────────────────────────────────────────────────────────

// Current returns the latest system snapshot.
func (c *Collector) Current() SystemSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.current
}

// TrafficHistory returns up to 24h of traffic data points.
func (c *Collector) TrafficHistory() []TrafficPoint {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]TrafficPoint, len(c.trafficHist))
	copy(out, c.trafficHist)
	return out
}

// ── Linux readers ─────────────────────────────────────────────────────────────

func readUptime() time.Duration {
	if runtime.GOOS != "linux" {
		return 0
	}
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return 0
	}
	secs, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return time.Duration(secs * float64(time.Second))
}

func readCPU() cpuSample {
	if runtime.GOOS != "linux" {
		return cpuSample{}
	}
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuSample{}
	}
	lines := strings.SplitN(string(data), "\n", 2)
	if len(lines) < 1 || !strings.HasPrefix(lines[0], "cpu ") {
		return cpuSample{}
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 5 {
		return cpuSample{}
	}
	// fields: cpu user nice system idle iowait irq softirq ...
	var total, idle uint64
	for i := 1; i < len(fields); i++ {
		v, _ := strconv.ParseUint(fields[i], 10, 64)
		total += v
		if i == 4 { // idle is the 4th value (0-indexed field 4)
			idle = v
		}
	}
	return cpuSample{idle: idle, total: total}
}

func readMemory() (total, used uint64) {
	if runtime.GOOS != "linux" {
		return 0, 0
	}
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	var memTotal, memAvailable uint64
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		val, _ := strconv.ParseUint(fields[1], 10, 64)
		val *= 1024 // convert kB to bytes
		switch fields[0] {
		case "MemTotal:":
			memTotal = val
		case "MemAvailable:":
			memAvailable = val
		}
	}
	if memTotal > memAvailable {
		used = memTotal - memAvailable
	}
	return memTotal, used
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func fmtDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60

	if days > 0 {
		return strconv.Itoa(days) + "d " + strconv.Itoa(hours) + "h " + strconv.Itoa(mins) + "m"
	}
	if hours > 0 {
		return strconv.Itoa(hours) + "h " + strconv.Itoa(mins) + "m"
	}
	return strconv.Itoa(mins) + "m"
}
