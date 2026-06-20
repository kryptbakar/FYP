package main

import (
	"crypto/rand"
	"fmt"
	"time"
)

// Host identifies the monitored host.
type Host struct {
	HostID   string `json:"host_id"`
	Hostname string `json:"hostname"`
	OS       string `json:"os,omitempty"`
	IP       string `json:"ip,omitempty"`
}

// Envelope is the v1 telemetry wire format (must match
// schema/telemetry/v1/envelope.schema.json — ingest-edge validates it).
type Envelope struct {
	SchemaVersion string            `json:"schema_version"`
	EventID       string            `json:"event_id"`
	AgentID       string            `json:"agent_id"`
	Host          Host              `json:"host"`
	CollectedAt   string            `json:"collected_at"`
	Kind          string            `json:"kind"`
	Labels        map[string]string `json:"labels,omitempty"`
	Payload       map[string]any    `json:"payload"`
}

// Sample is what a collector emits: a kind + payload. The factory wraps it into
// a full Envelope, so collectors don't need to know about identity/timestamps.
type Sample struct {
	Kind    string
	Payload map[string]any
}

// Factory stamps identity onto samples.
type Factory struct {
	agentID string
	host    Host
	labels  map[string]string
}

func newFactory(cfg Config) *Factory {
	return &Factory{
		agentID: cfg.AgentID,
		host:    Host{HostID: cfg.HostID, Hostname: cfg.Hostname, OS: cfg.OS},
		labels:  map[string]string{"env": "lab", "agent": "go-mvp"},
	}
}

func (f *Factory) wrap(s Sample) Envelope {
	return Envelope{
		SchemaVersion: "1.0",
		EventID:       uuid4(),
		AgentID:       f.agentID,
		Host:          f.host,
		CollectedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		Kind:          s.Kind,
		Labels:        f.labels,
		Payload:       s.Payload,
	}
}

// uuid4 generates a random RFC-4122 v4 UUID without external deps.
func uuid4() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
