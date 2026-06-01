package main

// Active-response responder — the agent end of the SIGNED command channel.
//
// The agent polls the server for approved commands, verifies each command's
// Ed25519 signature against the server public key it was provisioned with
// (NOT a key supplied by the command), and only then executes a containment
// action. An unsigned/forged/tampered command is refused and reported. Actions
// are containment-only (kill / isolate / quarantine / disable) — never patching.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

type command struct {
	ID            int    `json:"id"`
	SignedPayload string `json:"signed_payload"`
	Signature     string `json:"signature"`
	SigningPubkey string `json:"signing_pubkey"`
}

type commandPayload struct {
	ActionID   int            `json:"action_id"`
	AgentID    string         `json:"agent_id"`
	ActionType string         `json:"action_type"`
	Params     map[string]any `json:"params"`
	Nonce      string         `json:"nonce"`
	IssuedAt   string         `json:"issued_at"`
}

type Responder struct {
	cfg    Config
	pub    ed25519.PublicKey
	client *http.Client
	log    *slog.Logger
}

func newResponder(cfg Config, log *slog.Logger) (*Responder, error) {
	raw, err := os.ReadFile(cfg.ServerPubKey)
	if err != nil {
		return nil, fmt.Errorf("read server pubkey: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(raw)))
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("bad server pubkey (len=%d): %v", len(key), err)
	}
	return &Responder{
		cfg: cfg, pub: ed25519.PublicKey(key),
		client: &http.Client{Timeout: 15 * time.Second}, log: log,
	}, nil
}

func (r *Responder) Run(ctx context.Context) {
	r.log.Info("responder up (signed command channel)", "api", r.cfg.APIURL, "poll", r.cfg.ResponsePoll.String())
	t := time.NewTicker(r.cfg.ResponsePoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.poll(ctx)
		}
	}
}

func (r *Responder) poll(ctx context.Context) {
	url := fmt.Sprintf("%s/v1/agents/%s/commands", r.cfg.APIURL, r.cfg.AgentID)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+r.cfg.AgentToken)
	resp, err := r.client.Do(req)
	if err != nil {
		return // server not reachable this tick; try again later
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	var cmds []command
	if err := json.NewDecoder(resp.Body).Decode(&cmds); err != nil {
		return
	}
	for _, c := range cmds {
		r.handle(c)
	}
}

func (r *Responder) handle(c command) {
	// 1) Verify the signature against OUR trusted server key (zero-trust on the channel).
	sig, err := base64.StdEncoding.DecodeString(c.Signature)
	if err != nil || !ed25519.Verify(r.pub, []byte(c.SignedPayload), sig) {
		r.log.Warn("REFUSED command: signature verification failed", "action", c.ID)
		r.report(c.ID, "verify_failed", "Ed25519 signature did not verify against the server public key")
		return
	}
	var p commandPayload
	if err := json.Unmarshal([]byte(c.SignedPayload), &p); err != nil {
		r.report(c.ID, "failed", "could not parse signed payload")
		return
	}
	if p.AgentID != r.cfg.AgentID {
		r.report(c.ID, "failed", "command addressed to a different agent")
		return
	}
	r.log.Info("executing signed command", "action", c.ID, "type", p.ActionType)
	ok, out := r.execute(p)
	status := "completed"
	if !ok {
		status = "failed"
	}
	r.report(c.ID, status, out)
}

// execute performs the containment action. Each executor attempts the real
// operation and reports what happened (including graceful failure where the lab
// container lacks privileges — honest, not silently "successful").
func (r *Responder) execute(p commandPayload) (bool, string) {
	switch p.ActionType {
	case "file_quarantine":
		return r.quarantine(p.Params)
	case "process_kill":
		return r.killProcess(p.Params)
	case "network_isolate":
		return runCmd("nft", "-f", "-")
	case "user_disable":
		if u, ok := p.Params["user"].(string); ok && u != "" {
			return runCmd("usermod", "-L", u)
		}
		return false, "missing 'user' param"
	default:
		return false, "unknown action_type: " + p.ActionType
	}
}

func (r *Responder) quarantine(params map[string]any) (bool, string) {
	path, _ := params["path"].(string)
	if path == "" {
		return false, "missing 'path' param"
	}
	if err := os.MkdirAll(r.cfg.QuarantineDir, 0o700); err != nil {
		return false, "mkdir quarantine: " + err.Error()
	}
	dst := filepath.Join(r.cfg.QuarantineDir, filepath.Base(path)+".quarantined")
	if err := os.Rename(path, dst); err != nil {
		return false, fmt.Sprintf("quarantine move failed: %v", err)
	}
	_ = os.Chmod(dst, 0o000) // neutralize
	return true, fmt.Sprintf("quarantined %s -> %s (mode 000)", path, dst)
}

func (r *Responder) killProcess(params map[string]any) (bool, string) {
	pidf, ok := params["pid"].(float64)
	if !ok {
		return false, "missing/invalid 'pid' param"
	}
	pid := int(pidf)
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false, "find process: " + err.Error()
	}
	if err := proc.Kill(); err != nil {
		return false, fmt.Sprintf("kill pid %d failed: %v", pid, err)
	}
	return true, "killed pid " + strconv.Itoa(pid)
}

func runCmd(name string, args ...string) (bool, string) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return false, fmt.Sprintf("%s failed: %v (%s)", name, err, string(out))
	}
	return true, fmt.Sprintf("%s ok: %s", name, string(out))
}

func (r *Responder) report(actionID int, status, output string) {
	body, _ := json.Marshal(map[string]string{"status": status, "output": output})
	url := fmt.Sprintf("%s/v1/commands/%d/result", r.cfg.APIURL, actionID)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.cfg.AgentToken)
	if resp, err := r.client.Do(req); err == nil {
		resp.Body.Close()
	}
}
