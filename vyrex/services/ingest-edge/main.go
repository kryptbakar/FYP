// ingest-edge — the stateless edge of the ingestion backbone.
//
// Responsibilities (and ONLY these — no business logic, no DB):
//  1. Terminate mutual TLS and authenticate the agent (client cert + bearer token).
//  2. Validate every telemetry envelope against the versioned JSON Schema.
//  3. Enqueue accepted envelopes onto NATS JetStream (subject telemetry.v1.<kind>).
//
// Keeping this layer dumb and stateless is what lets it scale horizontally and
// makes back-pressure a property of the broker, not of a database.
package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	_ "embed"

	"github.com/nats-io/nats.go"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

// The telemetry schema is baked into the binary at build time from the single
// source of truth in schema/telemetry/v1/ (the Dockerfile copies it in).
//
//go:embed schema/envelope.schema.json
var schemaBytes []byte

const maxBodyBytes = 8 << 20 // 8 MiB cap per request

type config struct {
	addr          string // mTLS telemetry listener
	healthAddr    string // plain-HTTP health/ready listener (no client cert needed)
	tlsEnabled    bool
	tlsCert       string
	tlsKey        string
	clientCA      string // if set, mutual TLS is required
	agentToken    string // shared bearer token; "" disables the token check
	natsURL       string
	stream        string
	subjectPrefix string // e.g. "telemetry.v1"
}

func loadConfig() config {
	return config{
		addr:          env("INGEST_ADDR", ":8443"),
		healthAddr:    env("INGEST_HEALTH_ADDR", ":8081"),
		tlsEnabled:    env("INGEST_TLS_ENABLED", "true") == "true",
		tlsCert:       env("INGEST_TLS_CERT", "/certs/server.crt"),
		tlsKey:        env("INGEST_TLS_KEY", "/certs/server.key"),
		clientCA:      env("INGEST_CLIENT_CA", "/certs/ca.crt"),
		agentToken:    env("INGEST_AGENT_TOKEN", ""),
		natsURL:       env("NATS_URL", "nats://nats:4222"),
		stream:        env("INGEST_STREAM", "TELEMETRY"),
		subjectPrefix: env("INGEST_SUBJECT_PREFIX", "telemetry.v1"),
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

type server struct {
	cfg    config
	js     nats.JetStreamContext
	nc     *nats.Conn
	schema *jsonschema.Schema
	log    *slog.Logger
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg := loadConfig()

	schema, err := compileSchema()
	if err != nil {
		log.Error("compile schema", "err", err)
		os.Exit(1)
	}

	nc, js, err := connectJetStream(cfg, log)
	if err != nil {
		log.Error("connect jetstream", "err", err)
		os.Exit(1)
	}
	defer nc.Drain()

	srv := &server{cfg: cfg, js: js, nc: nc, schema: schema, log: log}

	// Health/ready live on a separate plain-HTTP port so probes don't need a
	// client certificate (the mTLS listener would otherwise reject them).
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("GET /health", srv.handleHealth)
	healthMux.HandleFunc("GET /ready", srv.handleReady)
	healthSrv := &http.Server{Addr: cfg.healthAddr, Handler: healthMux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := healthSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("health server", "err", err)
		}
	}()

	// Telemetry ingest on the mTLS listener.
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/telemetry", srv.handleTelemetry)
	httpSrv := &http.Server{
		Addr:              cfg.addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		var err error
		if cfg.tlsEnabled {
			tlsCfg, terr := buildTLS(cfg)
			if terr != nil {
				log.Error("build tls", "err", terr)
				os.Exit(1)
			}
			httpSrv.TLSConfig = tlsCfg
			log.Info("ingest-edge listening (mTLS)", "addr", cfg.addr, "mtls", cfg.clientCA != "")
			err = httpSrv.ListenAndServeTLS(cfg.tlsCert, cfg.tlsKey)
		} else {
			log.Warn("ingest-edge listening WITHOUT TLS (lab fallback)", "addr", cfg.addr)
			err = httpSrv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http server", "err", err)
			os.Exit(1)
		}
	}()

	// Graceful shutdown.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
	_ = healthSrv.Shutdown(ctx)
}

func compileSchema() (*jsonschema.Schema, error) {
	c := jsonschema.NewCompiler()
	c.AssertFormat = true // enforce uuid / date-time formats, not just annotate
	if err := c.AddResource("envelope.schema.json", bytes.NewReader(schemaBytes)); err != nil {
		return nil, err
	}
	return c.Compile("envelope.schema.json")
}

func connectJetStream(cfg config, log *slog.Logger) (*nats.Conn, nats.JetStreamContext, error) {
	nc, err := nats.Connect(cfg.natsURL,
		nats.Name("ingest-edge"),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(time.Second),
	)
	if err != nil {
		return nil, nil, err
	}
	js, err := nc.JetStream()
	if err != nil {
		return nil, nil, err
	}
	// Ensure the durable stream exists (idempotent).
	if _, err := js.StreamInfo(cfg.stream); err != nil {
		_, err = js.AddStream(&nats.StreamConfig{
			Name:       cfg.stream,
			Subjects:   []string{cfg.subjectPrefix + ".>"},
			Storage:    nats.FileStorage,
			Retention:  nats.LimitsPolicy,
			Discard:    nats.DiscardOld,
			MaxAge:     7 * 24 * time.Hour,
			Duplicates: 2 * time.Minute, // MsgId dedup window
		})
		if err != nil {
			return nil, nil, fmt.Errorf("add stream: %w", err)
		}
		log.Info("created jetstream stream", "stream", cfg.stream, "subjects", cfg.subjectPrefix+".>")
	}
	return nc, js, nil
}

func buildTLS(cfg config) (*tls.Config, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.clientCA != "" {
		caPEM, err := os.ReadFile(cfg.clientCA)
		if err != nil {
			return nil, fmt.Errorf("read client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("client CA: no certs parsed")
		}
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert // enforce mTLS
	}
	return tlsCfg, nil
}

func (s *server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) handleReady(w http.ResponseWriter, _ *http.Request) {
	if s.nc.Status() != nats.CONNECTED {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not_ready", "nats": s.nc.Status().String()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready", "nats": "connected"})
}

// ingestResult is the per-request summary returned to the agent.
type ingestResult struct {
	Accepted int      `json:"accepted"`
	Rejected int      `json:"rejected"`
	Errors   []string `json:"errors,omitempty"`
}

func (s *server) handleTelemetry(w http.ResponseWriter, r *http.Request) {
	// --- AuthN ---
	cn, err := s.authenticate(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "body too large"})
		return
	}

	// Accept either a single envelope object or a JSON array (batch).
	envelopes, err := splitEnvelopes(body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}

	res := ingestResult{}
	for i, raw := range envelopes {
		if perr := s.processOne(raw, cn); perr != nil {
			res.Rejected++
			res.Errors = append(res.Errors, fmt.Sprintf("item %d: %s", i, perr.Error()))
			continue
		}
		res.Accepted++
	}

	status := http.StatusOK
	if res.Accepted == 0 && res.Rejected > 0 {
		status = http.StatusBadRequest
	}
	s.log.Info("telemetry", "cn", cn, "accepted", res.Accepted, "rejected", res.Rejected)
	writeJSON(w, status, res)
}

// authenticate enforces the bearer token (if configured) and returns the mTLS
// client-cert CN (empty string when TLS/mTLS is off).
func (s *server) authenticate(r *http.Request) (string, error) {
	if s.cfg.agentToken != "" {
		const p = "Bearer "
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, p) ||
			subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(h, p)), []byte(s.cfg.agentToken)) != 1 {
			return "", errors.New("invalid or missing bearer token")
		}
	}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return r.TLS.PeerCertificates[0].Subject.CommonName, nil
	}
	if s.cfg.tlsEnabled && s.cfg.clientCA != "" {
		return "", errors.New("client certificate required")
	}
	return "", nil
}

// processOne validates a single envelope and publishes it to JetStream.
func (s *server) processOne(raw json.RawMessage, cn string) error {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("not an object: %w", err)
	}
	if err := s.schema.Validate(doc); err != nil {
		return fmt.Errorf("schema: %v", err)
	}

	agentID, _ := doc["agent_id"].(string)
	kind, _ := doc["kind"].(string)
	eventID, _ := doc["event_id"].(string)

	// When mTLS is on, the cert identity must match the claimed agent.
	if cn != "" && agentID != cn {
		return fmt.Errorf("agent_id %q does not match client cert CN %q", agentID, cn)
	}

	// Stamp receipt time; preserve everything else.
	doc["ingested_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	out, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("re-marshal: %w", err)
	}

	subject := s.cfg.subjectPrefix + "." + kind
	if _, err := s.js.Publish(subject, out, nats.MsgId(eventID)); err != nil {
		return fmt.Errorf("publish: %w", err)
	}
	return nil
}

// splitEnvelopes returns the list of raw envelopes, handling both a single
// object and an array.
func splitEnvelopes(body []byte) ([]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, errors.New("empty body")
	}
	if trimmed[0] == '[' {
		var arr []json.RawMessage
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return nil, err
		}
		return arr, nil
	}
	return []json.RawMessage{trimmed}, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
