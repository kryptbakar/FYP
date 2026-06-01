package main

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the agent's full runtime configuration, sourced from environment
// variables so it works cleanly under Docker/K3s. Sensible defaults let it run
// against the local stack with no config at all.
type Config struct {
	AgentID  string
	HostID   string
	Hostname string
	OS       string

	// Shipping to ingest-edge over mTLS.
	IngestURL  string
	AgentToken string
	CACert     string
	ClientCert string
	ClientKey  string
	BatchSize  int
	FlushEvery time.Duration

	// Collector toggles.
	EnableSysinfo bool
	EnableNetwork bool
	EnableOsquery bool
	EnableFIM     bool
	EnableEBPF    bool // stage-in (off by default in the MVP)
	EnableYARA    bool // stage-in (off by default in the MVP)

	// Collector intervals.
	SysinfoEvery time.Duration
	NetworkEvery time.Duration
	OsqueryEvery time.Duration
	FIMEvery     time.Duration

	// FIM watch paths.
	FIMPaths    []string
	FIMMaxFiles int

	// Resource caps (the agent must be a polite guest on monitored hosts).
	MaxProcs   int
	MemLimitMB int

	// Active response (Phase 6): the signed command channel.
	ResponseEnabled bool
	APIURL          string
	ServerPubKey    string // base64 raw Ed25519 public key the agent verifies against
	ResponsePoll    time.Duration
	QuarantineDir   string
}

func loadConfig() Config {
	host, _ := os.Hostname()
	return Config{
		AgentID:  env("AGENT_ID", "agent-001"),
		HostID:   env("AGENT_HOST_ID", host),
		Hostname: env("HOSTNAME_LABEL", host),
		OS:       env("AGENT_OS", "linux"),

		IngestURL:  env("INGEST_URL", "https://ingest-edge:8443/v1/telemetry"),
		AgentToken: env("INGEST_AGENT_TOKEN", ""),
		CACert:     env("CA_CERT", "/certs/ca.crt"),
		ClientCert: env("CLIENT_CERT", "/certs/agent-001.crt"),
		ClientKey:  env("CLIENT_KEY", "/certs/agent-001.key"),
		BatchSize:  envInt("AGENT_BATCH_SIZE", 50),
		FlushEvery: envSec("AGENT_FLUSH_SEC", 3),

		EnableSysinfo: envBool("ENABLE_SYSINFO", true),
		EnableNetwork: envBool("ENABLE_NETWORK", true),
		EnableOsquery: envBool("ENABLE_OSQUERY", true),
		EnableFIM:     envBool("ENABLE_FIM", true),
		EnableEBPF:    envBool("ENABLE_EBPF", false),
		EnableYARA:    envBool("ENABLE_YARA", false),

		SysinfoEvery: envSec("SYSINFO_INTERVAL_SEC", 10),
		NetworkEvery: envSec("NETWORK_INTERVAL_SEC", 15),
		OsqueryEvery: envSec("OSQUERY_INTERVAL_SEC", 30),
		FIMEvery:     envSec("FIM_INTERVAL_SEC", 20),

		FIMPaths:    splitCSV(env("FIM_PATHS", "/etc,/usr/bin")),
		FIMMaxFiles: envInt("FIM_MAX_FILES", 2000),

		MaxProcs:   envInt("AGENT_MAX_PROCS", 1),
		MemLimitMB: envInt("AGENT_MEM_LIMIT_MB", 128),

		ResponseEnabled: envBool("RESPONSE_ENABLED", false),
		APIURL:          env("API_URL", "http://api:8000"),
		ServerPubKey:    env("SERVER_PUBKEY", "/certs/command_signing.pub.b64"),
		ResponsePoll:    envSec("RESPONSE_POLL_SEC", 10),
		QuarantineDir:   env("QUARANTINE_DIR", "/quarantine"),
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envBool(k string, def bool) bool {
	if v := os.Getenv(k); v != "" {
		return v == "1" || strings.EqualFold(v, "true")
	}
	return def
}

func envSec(k string, def int) time.Duration {
	return time.Duration(envInt(k, def)) * time.Second
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
