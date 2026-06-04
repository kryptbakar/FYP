package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// YARACollector scans watched paths for IOC byte-patterns and emits yara_match events.
//
// HONEST SCOPE (verify on a Linux endpoint with real rules): this is a pure-Go *subset* of
// YARA — literal string and hex-string matching with an implicit "any of them" condition. It
// has no cgo dependency, so it builds and ships in the zero-dependency agent and runs on any
// host. It deliberately does NOT implement the full YARA grammar (regular-expression
// strings, count/offset conditions, PE/ELF modules, etc.). The production path is libyara via
// cgo with a compiled rules bundle; the Collector contract here is unchanged when that lands.
//
// Rules load from YARA_RULES_PATH, a small JSON file:
//
//	[ {"name": "EICAR_test_file", "strings": ["X5O!P%@AP..."]},
//	  {"name": "MZ_header",       "hex": ["4d5a9000"]} ]
type yaraRule struct {
	name     string
	patterns [][]byte // literal byte patterns (text, or decoded from hex)
}

type YARACollector struct {
	every    time.Duration
	paths    []string
	maxFiles int
	maxBytes int64
	rules    []yaraRule
}

func (c *YARACollector) Name() string            { return "yara" }
func (c *YARACollector) Interval() time.Duration { return c.every }

func (c *YARACollector) Collect(_ context.Context) ([]Sample, error) {
	if len(c.rules) == 0 {
		return nil, nil // no rules loaded -> nothing to do
	}
	var out []Sample
	count := 0
	for _, root := range c.paths {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !info.Mode().IsRegular() {
				return nil
			}
			if count >= c.maxFiles {
				return filepath.SkipAll
			}
			if info.Size() > c.maxBytes {
				return nil // skip large blobs (config-bounded)
			}
			count++
			data, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil
			}
			for _, rule := range c.rules {
				for _, pat := range rule.patterns {
					if len(pat) > 0 && bytes.Contains(data, pat) {
						out = append(out, Sample{Kind: "yara_match", Payload: map[string]any{
							"rule": rule.name, "path": path, "pattern_len": len(pat),
						}})
						break // one match per rule per file is enough
					}
				}
			}
			return nil
		})
	}
	return out, nil
}

// loadYARARules parses the small JSON rules file. A missing/invalid file yields no rules
// (the collector then no-ops) rather than failing the agent.
func loadYARARules(path string, log interface{ Warn(string, ...any) }) []yaraRule {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		log.Warn("yara rules file not found; yara collector idle", "path", path, "err", err)
		return nil
	}
	var raw []struct {
		Name    string   `json:"name"`
		Strings []string `json:"strings"`
		Hex     []string `json:"hex"`
	}
	if jerr := json.Unmarshal(b, &raw); jerr != nil {
		log.Warn("yara rules parse failed; yara collector idle", "err", jerr)
		return nil
	}
	var rules []yaraRule
	for _, r := range raw {
		var pats [][]byte
		for _, s := range r.Strings {
			if s != "" {
				pats = append(pats, []byte(s))
			}
		}
		for _, hx := range r.Hex {
			if d, e := hex.DecodeString(strings.ReplaceAll(hx, " ", "")); e == nil && len(d) > 0 {
				pats = append(pats, d)
			}
		}
		if len(pats) > 0 {
			rules = append(rules, yaraRule{name: r.Name, patterns: pats})
		}
	}
	return rules
}

func newYARACollector(every time.Duration, paths []string, maxFiles int, rulesPath string,
	log interface{ Warn(string, ...any) }) Collector {
	return &YARACollector{
		every:    every,
		paths:    paths,
		maxFiles: maxFiles,
		maxBytes: 10 << 20, // 10 MiB cap per file
		rules:    loadYARARules(rulesPath, log),
	}
}
