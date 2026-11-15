package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/statusharbor/lighthouse/internal/agent"
	"github.com/statusharbor/lighthouse/internal/transport"
)

var (
	dryRun = flag.Bool("dry-run", false,
		"print what the agent would send for one interval, as JSON lines, without connecting to Status Harbor")
	dryRunCollectors = flag.String("dry-run-collectors", "",
		"eBPF collectors to run in the dry run, comma-separated (e.g. discovery,incident,network,usage)")
	dryRunInterval = flag.Duration("dry-run-interval", 30*time.Second, "length of the dry-run interval")
)

// runDryRun runs the same collectors and sink the agent uses for one
// interval and prints every payload it would send: host facts, host metric
// samples (eBPF series included) and eBPF event envelopes. It opens no
// connection to Status Harbor (docs/eBPF/09-security-page.md in
// status-harbor, acceptance criterion 6).
func runDryRun(cfg *agent.Config) error {
	// stdout carries only the payloads; logs go to stderr.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	enc := json.NewEncoder(os.Stdout)
	emit := func(kind string, v any) error { return enc.Encode(map[string]any{"send": kind, "body": v}) }
	if err := emit("register.host_facts", agent.HostFacts()); err != nil {
		return err
	}

	hostname, _ := os.Hostname()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m, ebpfC, batcher := agent.NewEBPF(ctx, cfg, false, func(_ context.Context, events []transport.EBPFEnvelope) error {
		return emit("ebpf.events", transport.EBPFEventsRequest{Events: events})
	}, hostname, func() []agent.CheckDefinition { return nil }, nil)
	batched := make(chan struct{})
	if batcher != nil {
		go func() { batcher.Run(ctx); close(batched) }()
	} else {
		close(batched)
	}
	if m != nil && *dryRunCollectors != "" {
		m.Apply(strings.Split(*dryRunCollectors, ","))
	}

	collector := agent.NewMultiCollector(agent.NewLinuxCollectorWithRoots(cfg.Agent.ProcRoot, cfg.Agent.HostRoot), ebpfC)
	if _, err := collector.Collect(); err != nil { // baseline for rates and deltas
		return fmt.Errorf("collect: %w", err)
	}
	time.Sleep(*dryRunInterval)
	samples, err := collector.Collect()
	if err != nil {
		return fmt.Errorf("collect: %w", err)
	}
	if err := emit("host_metrics.samples", samples); err != nil {
		return err
	}
	if m != nil {
		for _, s := range m.Statuses() {
			if err := emit("heartbeat.ebpf_status", s); err != nil {
				return err
			}
		}
		m.Stop()
	}
	cancel()
	<-batched
	return nil
}
