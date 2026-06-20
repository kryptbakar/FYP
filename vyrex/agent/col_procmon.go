package main

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"
)

// ProcmonCollector observes process starts by snapshotting /proc and diffing the set of
// PIDs between scans. This is the dependency-free path that the eBPF stage-in was a
// placeholder for: it needs no kernel object, no CAP_BPF, and no cgo, so it builds and ships
// in the zero-dependency agent.
//
// HONEST SCOPE (verify on a Linux endpoint): this is poll-based /proc observation. At
// runtime it only does anything on Linux (it no-ops cleanly where /proc is absent, e.g. a
// dev build on Windows/macOS). It catches process *starts* (emitted as a process_event with
// action "exec"), but — unlike real eBPF — it can miss very short-lived processes that begin
// and exit between polls, and it does not see fork/exit or per-syscall context. The
// production upgrade is kernel-level tracing via cilium/ebpf (a compiled BPF object +
// CAP_BPF/CAP_PERFMON on a recent kernel); the Collector contract below does not change when
// that lands, so the scheduler/shipper stay untouched.
type ProcmonCollector struct {
	every    time.Duration
	baseline map[int]string // pid -> comm, established on the first (silent) scan
	primed   bool
}

func (c *ProcmonCollector) Name() string            { return "procmon" }
func (c *ProcmonCollector) Interval() time.Duration { return c.every }

func (c *ProcmonCollector) Collect(_ context.Context) ([]Sample, error) {
	cur := c.scan()
	if !c.primed {
		c.baseline = make(map[int]string, len(cur))
		for pid, info := range cur {
			c.baseline[pid] = info.comm
		}
		c.primed = true
		return nil, nil // first pass establishes a silent baseline
	}
	var out []Sample
	for pid, info := range cur {
		if _, existed := c.baseline[pid]; !existed {
			out = append(out, Sample{Kind: "process_event", Payload: map[string]any{
				"action": "exec", "pid": pid, "ppid": info.ppid,
				"comm": info.comm, "cmdline": info.cmdline,
			}})
		}
	}
	c.baseline = make(map[int]string, len(cur))
	for pid, info := range cur {
		c.baseline[pid] = info.comm
	}
	return out, nil
}

type procInfo struct {
	comm    string
	cmdline string
	ppid    int
}

func (c *ProcmonCollector) scan() map[int]procInfo {
	out := map[int]procInfo{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out // not Linux / no procfs: no-op
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // /proc has non-numeric entries too
		}
		base := "/proc/" + e.Name()
		out[pid] = procInfo{
			comm:    readTrimmed(base + "/comm"),
			cmdline: readCmdline(base + "/cmdline"),
			ppid:    readPPID(base + "/stat"),
		}
	}
	return out
}

func readTrimmed(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// readCmdline turns the NUL-separated /proc/<pid>/cmdline into a readable string.
func readCmdline(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
}

// readPPID pulls the parent pid out of /proc/<pid>/stat. comm (field 2) can contain spaces
// and parentheses, so we split after the final ')'.
func readPPID(statPath string) int {
	b, err := os.ReadFile(statPath)
	if err != nil {
		return 0
	}
	s := string(b)
	i := strings.LastIndex(s, ")")
	if i < 0 || i+2 >= len(s) {
		return 0
	}
	fields := strings.Fields(s[i+2:])
	if len(fields) < 2 {
		return 0
	}
	ppid, _ := strconv.Atoi(fields[1])
	return ppid
}
