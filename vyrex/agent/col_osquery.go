package main

import (
	"context"
	"encoding/json"
	"os/exec"
	"sync"
	"time"
)

// OsqueryCollector runs a small pack of osquery SQL via `osqueryi --json` and
// ships each result row as an osquery_result sample. This is the pragmatic
// "embed osqueryd" for the MVP: we drive the osquery binary rather than linking
// its Thrift extension API. If osqueryi isn't installed the collector degrades
// gracefully (logs once, emits nothing) so the agent still runs.
type OsqueryCollector struct {
	every   time.Duration
	bin     string
	queries map[string]string
	warnOne sync.Once
	log     interface{ Warn(string, ...any) }
}

func newOsqueryCollector(every time.Duration, log interface {
	Warn(string, ...any)
}) *OsqueryCollector {
	return &OsqueryCollector{
		every: every,
		bin:   "osqueryi",
		log:   log,
		queries: map[string]string{
			"os_version":       "SELECT name, version, platform FROM os_version;",
			"listening_ports":  "SELECT pid, port, protocol, address FROM listening_ports LIMIT 50;",
			"logged_in_users":  "SELECT user, host, tty, time FROM logged_in_users LIMIT 50;",
			"kernel_info":      "SELECT version, arguments FROM kernel_info;",
			"deb_packages":     "SELECT name, version FROM deb_packages LIMIT 100;",
		},
	}
}

func (c *OsqueryCollector) Name() string            { return "osquery" }
func (c *OsqueryCollector) Interval() time.Duration { return c.every }

func (c *OsqueryCollector) Collect(ctx context.Context) ([]Sample, error) {
	path, err := exec.LookPath(c.bin)
	if err != nil {
		c.warnOne.Do(func() { c.log.Warn("osqueryi not found; osquery collector disabled", "bin", c.bin) })
		return nil, nil
	}

	var out []Sample
	for name, q := range c.queries {
		rows, err := c.run(ctx, path, q)
		if err != nil {
			// One bad query shouldn't sink the rest (e.g., a table missing on this OS).
			c.log.Warn("osquery query failed", "query", name, "err", err)
			continue
		}
		for _, row := range rows {
			out = append(out, Sample{Kind: "osquery_result", Payload: map[string]any{
				"query_name": name,
				"columns":    row,
			}})
		}
	}
	return out, nil
}

func (c *OsqueryCollector) run(ctx context.Context, path, query string) ([]map[string]any, error) {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, path, "--json", query)
	stdout, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var rows []map[string]any
	if err := json.Unmarshal(stdout, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}
