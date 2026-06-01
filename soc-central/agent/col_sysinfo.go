package main

import (
	"bufio"
	"context"
	"os"
	"strconv"
	"strings"
	"time"
)

// SysinfoCollector reports basic host health as system_info metrics, read from
// /proc (Linux). CPU% is computed from the delta between successive /proc/stat
// reads, so the collector holds a little state.
type SysinfoCollector struct {
	every             time.Duration
	prevIdle, prevTot uint64
}

func (c *SysinfoCollector) Name() string            { return "sysinfo" }
func (c *SysinfoCollector) Interval() time.Duration { return c.every }

func (c *SysinfoCollector) Collect(_ context.Context) ([]Sample, error) {
	var out []Sample

	if pct, ok := c.cpuPercent(); ok {
		out = append(out, metric("cpu_pct", pct, "percent"))
	}
	if used, ok := memPercent(); ok {
		out = append(out, metric("mem_pct", used, "percent"))
	}
	if l1, ok := load1(); ok {
		out = append(out, metric("load1", l1, "ratio"))
	}
	// The agent watching its own footprint — useful for the resource-cap story.
	if rss, ok := selfRSSMB(); ok {
		out = append(out, metric("agent_rss_mb", rss, "megabytes"))
	}
	return out, nil
}

func metric(name string, value float64, unit string) Sample {
	return Sample{Kind: "system_info", Payload: map[string]any{"metric": name, "value": value, "unit": unit}}
}

func (c *SysinfoCollector) cpuPercent() (float64, bool) {
	idle, total, ok := readCPU()
	if !ok {
		return 0, false
	}
	defer func() { c.prevIdle, c.prevTot = idle, total }()
	if c.prevTot == 0 {
		return 0, false // first read: establish baseline only
	}
	dt := total - c.prevTot
	di := idle - c.prevIdle
	if dt == 0 {
		return 0, false
	}
	return round2(float64(dt-di) / float64(dt) * 100), true
}

func readCPU() (idle, total uint64, ok bool) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return 0, 0, false
	}
	fields := strings.Fields(sc.Text()) // cpu  user nice system idle iowait irq softirq steal ...
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, false
	}
	for i := 1; i < len(fields); i++ {
		v, _ := strconv.ParseUint(fields[i], 10, 64)
		total += v
		if i == 4 { // idle
			idle = v
		}
	}
	return idle, total, true
}

func memPercent() (float64, bool) {
	vals := readKV("/proc/meminfo")
	totalKB, ok1 := vals["MemTotal"]
	availKB, ok2 := vals["MemAvailable"]
	if !ok1 || !ok2 || totalKB == 0 {
		return 0, false
	}
	used := float64(totalKB-availKB) / float64(totalKB) * 100
	return round2(used), true
}

func load1() (float64, bool) {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return 0, false
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	return v, err == nil
}

func selfRSSMB() (float64, bool) {
	vals := readKV("/proc/self/status")
	rssKB, ok := vals["VmRSS"]
	if !ok {
		return 0, false
	}
	return round2(float64(rssKB) / 1024), true
}

// readKV parses "Key:  value kB"-style files into Key->value (numeric part).
func readKV(path string) map[string]uint64 {
	out := map[string]uint64{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), ":", 2)
		if len(parts) != 2 {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) == 0 {
			continue
		}
		if v, err := strconv.ParseUint(fields[0], 10, 64); err == nil {
			out[strings.TrimSpace(parts[0])] = v
		}
	}
	return out
}

func round2(f float64) float64 { return float64(int64(f*100+0.5)) / 100 }
