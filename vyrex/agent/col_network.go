package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// NetworkCollector reports TCP sockets (listening + established) as network_flow
// samples, parsed from /proc/net/tcp. This is the simple, dependency-free view;
// rich per-flow byte counts come from the eBPF collector (stage-in).
type NetworkCollector struct {
	every time.Duration
	max   int
}

func (c *NetworkCollector) Name() string            { return "network" }
func (c *NetworkCollector) Interval() time.Duration { return c.every }

func (c *NetworkCollector) Collect(_ context.Context) ([]Sample, error) {
	f, err := os.Open("/proc/net/tcp")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Sample
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() && len(out) < c.max {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		localIP, localPort, ok1 := parseV4(fields[1])
		remoteIP, remotePort, ok2 := parseV4(fields[2])
		if !ok1 || !ok2 {
			continue
		}
		switch fields[3] {
		case "0A": // LISTEN
			out = append(out, flow("inbound", localIP, localPort, "0.0.0.0", 0))
		case "01": // ESTABLISHED
			out = append(out, flow("outbound", localIP, localPort, remoteIP, remotePort))
		}
	}
	return out, nil
}

func flow(direction, localIP string, localPort int, remoteIP string, remotePort int) Sample {
	return Sample{Kind: "network_flow", Payload: map[string]any{
		"proto":       "tcp",
		"direction":   direction,
		"local_ip":    localIP,
		"local_port":  localPort,
		"remote_ip":   remoteIP,
		"remote_port": remotePort,
	}}
}

// parseV4 decodes a /proc/net/tcp "AABBCCDD:PPPP" field (little-endian hex IPv4
// + hex port) into dotted-quad + int.
func parseV4(s string) (ip string, port int, ok bool) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 || len(parts[0]) != 8 {
		return "", 0, false
	}
	var b [4]byte
	for i := 0; i < 4; i++ {
		v, err := strconv.ParseUint(parts[0][i*2:i*2+2], 16, 8)
		if err != nil {
			return "", 0, false
		}
		b[3-i] = byte(v) // little-endian -> network order
	}
	p, err := strconv.ParseUint(parts[1], 16, 32)
	if err != nil {
		return "", 0, false
	}
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3]), int(p), true
}
