package main

// Hunter — the agent end of the live-hunt channel (Velociraptor pattern).
//
// It polls the server for read-only collection tasks ("hunts"), gathers the requested
// artifact (running processes / listening ports / a file search / an osquery query), and
// returns the rows. It is COLLECTION-ONLY — it never runs a destructive action, so unlike
// the active-response responder it carries no signed-command machinery.
//
// HONEST SCOPE (verify on a Linux endpoint): the collectors read /proc and shell out to
// osqueryi, so they only produce real rows on Linux with those facilities present (elsewhere
// they return empty). This file builds and vets on any platform; end-to-end collection is
// verified on a real Linux host running the agent against the API.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Hunter struct {
	cfg    Config
	client *http.Client
	log    *slog.Logger
}

func newHunter(cfg Config, log *slog.Logger) *Hunter {
	return &Hunter{cfg: cfg, client: &http.Client{Timeout: 20 * time.Second}, log: log}
}

type huntSpec struct {
	ID       int    `json:"id"`
	Artifact string `json:"artifact"`
	Query    string `json:"query"`
	Target   string `json:"target"`
}

func (hn *Hunter) Run(ctx context.Context) {
	hn.log.Info("hunter up (live-hunt channel)", "api", hn.cfg.APIURL, "poll", hn.cfg.HuntPoll.String())
	t := time.NewTicker(hn.cfg.HuntPoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			hn.poll(ctx)
		}
	}
}

func (hn *Hunter) poll(ctx context.Context) {
	url := fmt.Sprintf("%s/v1/agents/%s/hunts", hn.cfg.APIURL, hn.cfg.AgentID)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+hn.cfg.AgentToken)
	resp, err := hn.client.Do(req)
	if err != nil {
		return // server unreachable this tick
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	var hunts []huntSpec
	if json.NewDecoder(resp.Body).Decode(&hunts) != nil {
		return
	}
	for _, h := range hunts {
		rows := hn.collect(h)
		hn.submit(h.ID, rows)
		hn.log.Info("hunt collected", "hunt", h.ID, "artifact", h.Artifact, "rows", len(rows))
	}
}

func (hn *Hunter) collect(h huntSpec) []map[string]any {
	switch h.Artifact {
	case "processes":
		return collectProcesses()
	case "listening_ports":
		return collectListeningPorts()
	case "file_search":
		return collectFileSearch(h.Query)
	case "osquery":
		return collectOsquery(h.Query)
	default:
		return nil
	}
}

func collectProcesses() []map[string]any {
	var out []map[string]any
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		base := "/proc/" + e.Name()
		out = append(out, map[string]any{
			"pid": pid, "ppid": readPPID(base + "/stat"),
			"comm": readTrimmed(base + "/comm"), "cmdline": readCmdline(base + "/cmdline"),
		})
	}
	return out
}

func collectListeningPorts() []map[string]any {
	var out []map[string]any
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for i, ln := range strings.Split(string(b), "\n") {
			if i == 0 {
				continue // header row
			}
			fields := strings.Fields(ln)
			if len(fields) < 4 || fields[3] != "0A" { // 0A = TCP LISTEN
				continue
			}
			lp := strings.Split(fields[1], ":")
			if len(lp) != 2 {
				continue
			}
			port, _ := strconv.ParseInt(lp[1], 16, 32)
			out = append(out, map[string]any{"proto": filepath.Base(f), "port": int(port), "state": "LISTEN"})
		}
	}
	return out
}

func collectFileSearch(glob string) []map[string]any {
	if glob == "" {
		glob = "/tmp/*"
	}
	matches, err := filepath.Glob(glob)
	if err != nil {
		return nil
	}
	var out []map[string]any
	for _, m := range matches {
		info, serr := os.Stat(m)
		if serr != nil {
			continue
		}
		out = append(out, map[string]any{
			"path": m, "size": info.Size(), "mode": info.Mode().String(),
			"modified": info.ModTime().UTC().Format(time.RFC3339),
		})
		if len(out) >= 500 {
			break
		}
	}
	return out
}

func collectOsquery(query string) []map[string]any {
	if query == "" {
		return nil
	}
	var buf bytes.Buffer
	cmd := exec.Command("osqueryi", "--json", query)
	cmd.Stdout = &buf
	if err := cmd.Run(); err != nil {
		return nil // osqueryi absent or query failed
	}
	var rows []map[string]any
	_ = json.Unmarshal(buf.Bytes(), &rows)
	return rows
}

func (hn *Hunter) submit(huntID int, rows []map[string]any) {
	body, _ := json.Marshal(map[string]any{"asset_id": hn.cfg.HostID, "rows": rows})
	url := fmt.Sprintf("%s/v1/hunts/%d/results", hn.cfg.APIURL, huntID)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+hn.cfg.AgentToken)
	req.Header.Set("agent-id", hn.cfg.AgentID)
	if resp, err := hn.client.Do(req); err == nil {
		resp.Body.Close()
	}
}
