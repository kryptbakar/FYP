package main

import (
	"context"
	"log/slog"
	"time"
)

// Collector is the contract every telemetry source implements. Adding a new
// source (eBPF, YARA, a new osquery pack) is just a new Collector.
type Collector interface {
	Name() string
	Interval() time.Duration
	Collect(ctx context.Context) ([]Sample, error)
}

// Scheduler runs each collector on its own ticker and feeds samples (wrapped
// into envelopes) to the shipper.
type Scheduler struct {
	factory    *Factory
	shipper    *Shipper
	collectors []Collector
	log        *slog.Logger
}

func newScheduler(f *Factory, s *Shipper, log *slog.Logger, cols ...Collector) *Scheduler {
	return &Scheduler{factory: f, shipper: s, collectors: cols, log: log}
}

// Run starts one goroutine per collector and blocks until ctx is cancelled.
func (sc *Scheduler) Run(ctx context.Context) {
	done := make(chan struct{}, len(sc.collectors))
	for _, c := range sc.collectors {
		go func(c Collector) {
			defer func() { done <- struct{}{} }()
			sc.runOne(ctx, c)
		}(c)
	}
	<-ctx.Done()
	for range sc.collectors {
		<-done
	}
}

func (sc *Scheduler) runOne(ctx context.Context, c Collector) {
	// Collect once immediately, then on the interval.
	sc.tick(ctx, c)
	t := time.NewTicker(c.Interval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sc.tick(ctx, c)
		}
	}
}

func (sc *Scheduler) tick(ctx context.Context, c Collector) {
	samples, err := c.Collect(ctx)
	if err != nil {
		sc.log.Warn("collect failed", "collector", c.Name(), "err", err)
		return
	}
	for _, s := range samples {
		// ctx-aware send so shutdown can't deadlock on a full buffer.
		select {
		case sc.shipper.ch <- sc.factory.wrap(s):
		case <-ctx.Done():
			return
		}
	}
	if len(samples) > 0 {
		sc.log.Info("collected", "collector", c.Name(), "samples", len(samples))
	}
}
