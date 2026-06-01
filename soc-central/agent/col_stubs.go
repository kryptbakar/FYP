package main

import (
	"context"
	"sync"
	"time"
)

// --- Stage-in collectors -----------------------------------------------------
//
// These satisfy the Collector interface and are wired into the registry, but
// are OFF by default in the MVP (ENABLE_EBPF / ENABLE_YARA = false). They make
// the extension points concrete so a later phase can drop in the real
// implementation without touching the scheduler/shipper.
//
//   eBPF  — process exec/fork/exit + per-flow network observation via
//           cilium/ebpf. Needs a compiled BPF object, CAP_BPF/CAP_PERFMON, and a
//           recent kernel; hence not enabled in the lab container.
//   YARA  — file/memory IOC scanning via libyara (cgo). Needs the YARA shared
//           lib and a rules bundle mounted into the agent.

type stubCollector struct {
	name string
	what string
	every time.Duration
	warn sync.Once
	log  interface{ Warn(string, ...any) }
}

func (s *stubCollector) Name() string            { return s.name }
func (s *stubCollector) Interval() time.Duration { return s.every }

func (s *stubCollector) Collect(_ context.Context) ([]Sample, error) {
	s.warn.Do(func() {
		s.log.Warn("stage-in collector enabled but not implemented in MVP", "collector", s.name, "needs", s.what)
	})
	return nil, nil
}

func newEBPFCollector(every time.Duration, log interface{ Warn(string, ...any) }) Collector {
	return &stubCollector{name: "ebpf", what: "compiled BPF object + CAP_BPF + recent kernel", every: every, log: log}
}

func newYARACollector(every time.Duration, log interface{ Warn(string, ...any) }) Collector {
	return &stubCollector{name: "yara", what: "libyara (cgo) + mounted rules bundle", every: every, log: log}
}
