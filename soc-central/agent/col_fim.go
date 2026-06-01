package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const fimMaxHashBytes = 5 << 20 // hash files up to 5 MiB; larger -> size+mtime fingerprint

// FIMCollector does file-integrity monitoring by polling: it walks the watched
// paths, fingerprints each file, and emits fim_event samples for files that were
// created / modified / deleted since the last scan. The first scan establishes a
// silent baseline.
//
// MVP note: polling is simple, container-friendly, and needs no privileges. The
// production path is event-driven fanotify/auditd (no full rescan, instant
// detection) — see DECISIONS D-015. The interface here doesn't change when we
// swap the mechanism.
type FIMCollector struct {
	every    time.Duration
	paths    []string
	maxFiles int
	baseline map[string]string // path -> fingerprint
	primed   bool
}

func (c *FIMCollector) Name() string            { return "fim" }
func (c *FIMCollector) Interval() time.Duration { return c.every }

func (c *FIMCollector) Collect(_ context.Context) ([]Sample, error) {
	current := c.scan()

	if !c.primed {
		c.baseline = current
		c.primed = true
		return nil, nil // baseline only; no events on first pass
	}

	var out []Sample
	for path, fp := range current {
		old, existed := c.baseline[path]
		if !existed {
			out = append(out, fimEvent(path, "created", fp))
		} else if old != fp {
			out = append(out, fimEvent(path, "modified", fp))
		}
	}
	for path := range c.baseline {
		if _, ok := current[path]; !ok {
			out = append(out, fimEvent(path, "deleted", ""))
		}
	}
	c.baseline = current
	return out, nil
}

func fimEvent(path, change, fp string) Sample {
	p := map[string]any{"path": path, "change": change}
	if fp != "" {
		p["sha256"] = fp
	}
	return Sample{Kind: "fim_event", Payload: p}
}

func (c *FIMCollector) scan() map[string]string {
	out := make(map[string]string)
	count := 0
	for _, root := range c.paths {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // unreadable entry: skip, don't abort the walk
			}
			if info.IsDir() {
				return nil
			}
			if !info.Mode().IsRegular() {
				return nil
			}
			if count >= c.maxFiles {
				return filepath.SkipAll
			}
			out[path] = fingerprint(path, info)
			count++
			return nil
		})
	}
	return out
}

// fingerprint is the SHA-256 of file contents for small files, or a cheap
// size+mtime token for large ones (avoids hashing huge blobs every scan).
func fingerprint(path string, info os.FileInfo) string {
	if info.Size() > fimMaxHashBytes {
		return fmt.Sprintf("meta:%d:%d", info.Size(), info.ModTime().UnixNano())
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Sprintf("meta:%d:%d", info.Size(), info.ModTime().UnixNano())
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Sprintf("meta:%d:%d", info.Size(), info.ModTime().UnixNano())
	}
	return hex.EncodeToString(h.Sum(nil))
}
