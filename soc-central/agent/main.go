// SOC Central endpoint agent (MVP).
//
// A lightweight, resource-capped Go agent for Linux hosts. It runs a set of
// collectors (sysinfo, network, osquery, file-integrity monitoring; eBPF/YARA
// staged in) and ships the resulting telemetry to ingest-edge over mutual TLS,
// using the same versioned envelope every other layer speaks.
//
// Linux-first by design (reads /proc, runs osquery). Windows agent parity is a
// later roadmap item, not part of the MVP.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"sync"
	"syscall"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg := loadConfig()

	// --- Resource caps: be a polite guest on monitored hosts. ---
	if cfg.MaxProcs > 0 {
		runtime.GOMAXPROCS(cfg.MaxProcs)
	}
	if cfg.MemLimitMB > 0 {
		debug.SetMemoryLimit(int64(cfg.MemLimitMB) << 20) // soft limit: GC works harder near it
	}
	log.Info("agent starting",
		"agent_id", cfg.AgentID, "host", cfg.Hostname,
		"gomaxprocs", runtime.GOMAXPROCS(0), "mem_limit_mb", cfg.MemLimitMB,
		"ingest", cfg.IngestURL)

	shipper, err := newShipper(cfg, log)
	if err != nil {
		log.Error("init shipper", "err", err)
		os.Exit(1)
	}

	collectors := buildCollectors(cfg, log)
	if len(collectors) == 0 {
		log.Error("no collectors enabled")
		os.Exit(1)
	}
	names := make([]string, 0, len(collectors))
	for _, c := range collectors {
		names = append(names, c.Name())
	}
	log.Info("collectors enabled", "collectors", names)

	sched := newScheduler(newFactory(cfg), shipper, log, collectors...)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); shipper.Run(ctx) }()
	go func() { defer wg.Done(); sched.Run(ctx) }()

	// Active-response responder (signed command channel).
	if cfg.ResponseEnabled {
		if responder, rerr := newResponder(cfg, log); rerr != nil {
			log.Error("responder disabled", "err", rerr)
		} else {
			wg.Add(1)
			go func() { defer wg.Done(); responder.Run(ctx) }()
		}
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Info("shutting down; flushing telemetry")
	cancel()
	wg.Wait()
	log.Info("stopped")
}

// buildCollectors assembles the enabled collectors from config.
func buildCollectors(cfg Config, log *slog.Logger) []Collector {
	var cs []Collector
	if cfg.EnableSysinfo {
		cs = append(cs, &SysinfoCollector{every: cfg.SysinfoEvery})
	}
	if cfg.EnableNetwork {
		cs = append(cs, &NetworkCollector{every: cfg.NetworkEvery, max: 100})
	}
	if cfg.EnableOsquery {
		cs = append(cs, newOsqueryCollector(cfg.OsqueryEvery, log))
	}
	if cfg.EnableFIM {
		cs = append(cs, &FIMCollector{every: cfg.FIMEvery, paths: cfg.FIMPaths, maxFiles: cfg.FIMMaxFiles})
	}
	if cfg.EnableEBPF {
		cs = append(cs, newEBPFCollector(cfg.SysinfoEvery, log))
	}
	if cfg.EnableYARA {
		cs = append(cs, newYARACollector(cfg.OsqueryEvery, log))
	}
	return cs
}
