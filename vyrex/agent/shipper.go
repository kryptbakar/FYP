package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"
)

// Shipper batches envelopes and POSTs them to ingest-edge over mutual TLS.
// A bounded channel gives the agent its own back-pressure: if ingest-edge is
// unreachable, collectors block rather than the agent ballooning in memory.
type Shipper struct {
	url    string
	token  string
	client *http.Client
	ch     chan Envelope
	batch  int
	flush  time.Duration
	log    *slog.Logger
}

func newShipper(cfg Config, log *slog.Logger) (*Shipper, error) {
	tlsCfg, err := buildClientTLS(cfg)
	if err != nil {
		return nil, err
	}
	return &Shipper{
		url:   cfg.IngestURL,
		token: cfg.AgentToken,
		client: &http.Client{
			Timeout:   20 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
		ch:    make(chan Envelope, cfg.BatchSize*4),
		batch: cfg.BatchSize,
		flush: cfg.FlushEvery,
		log:   log,
	}, nil
}

func buildClientTLS(cfg Config) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}
	caPEM, err := os.ReadFile(cfg.CACert)
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA: no certs parsed")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// Submit hands an envelope to the shipper (blocks if the buffer is full).
func (s *Shipper) Submit(e Envelope) { s.ch <- e }

// Run accumulates envelopes and flushes on batch-size or the flush interval,
// until ctx is cancelled (then it drains what's left).
func (s *Shipper) Run(ctx context.Context) {
	ticker := time.NewTicker(s.flush)
	defer ticker.Stop()
	buf := make([]Envelope, 0, s.batch)

	for {
		select {
		case <-ctx.Done():
			s.drain(&buf)
			return
		case e := <-s.ch:
			buf = append(buf, e)
			if len(buf) >= s.batch {
				s.send(buf)
				buf = buf[:0]
			}
		case <-ticker.C:
			if len(buf) > 0 {
				s.send(buf)
				buf = buf[:0]
			}
		}
	}
}

func (s *Shipper) drain(buf *[]Envelope) {
	// Pull anything still queued, then flush.
	for {
		select {
		case e := <-s.ch:
			*buf = append(*buf, e)
		default:
			if len(*buf) > 0 {
				s.send(*buf)
			}
			return
		}
	}
}

// send POSTs a batch with bounded exponential-backoff retry. Ingest-edge may be
// briefly unavailable (starting up, rolling) — telemetry should survive that.
func (s *Shipper) send(batch []Envelope) {
	body, err := json.Marshal(batch)
	if err != nil {
		s.log.Error("marshal batch", "err", err)
		return
	}
	backoff := 500 * time.Millisecond
	for attempt := 1; attempt <= 5; attempt++ {
		if err = s.post(body); err == nil {
			s.log.Info("shipped", "count", len(batch))
			return
		}
		s.log.Warn("ship failed; retrying", "attempt", attempt, "err", err)
		time.Sleep(backoff)
		if backoff < 8*time.Second {
			backoff *= 2
		}
	}
	s.log.Error("dropping batch after retries", "count", len(batch))
}

func (s *Shipper) post(body []byte) error {
	req, err := http.NewRequest(http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("http %d: %s", resp.StatusCode, string(b))
	}
	io.Copy(io.Discard, resp.Body)
	return nil
}
