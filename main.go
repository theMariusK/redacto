package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type pattern_entry bpf redactor.c

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"gopkg.in/yaml.v3"
)

type Rule struct {
	Original    string `yaml:"original"`
	Placeholder string `yaml:"placeholder"`
}

type Config struct {
	Rules []Rule `yaml:"rules"`
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if len(cfg.Rules) == 0 {
		return nil, fmt.Errorf("config has no rules")
	}
	if len(cfg.Rules) > 8 {
		return nil, fmt.Errorf("too many rules: %d (max 8)", len(cfg.Rules))
	}

	for i, r := range cfg.Rules {
		if len(r.Original) == 0 || len(r.Placeholder) == 0 {
			return nil, fmt.Errorf("rule %d: original and placeholder must be non-empty", i)
		}
		if len(r.Original) > 16 {
			return nil, fmt.Errorf("rule %d: original too long (%d bytes, max 16)", i, len(r.Original))
		}
		if len(r.Placeholder) > 16 {
			return nil, fmt.Errorf("rule %d: placeholder too long (%d bytes, max 16)", i, len(r.Placeholder))
		}
		if len(r.Original) != len(r.Placeholder) {
			return nil, fmt.Errorf("rule %d: original (%d bytes) and placeholder (%d bytes) must be the same length",
				i, len(r.Original), len(r.Placeholder))
		}
	}

	return &cfg, nil
}

func main() {
	configPath := flag.String("config", "", "Path to redaction config YAML file")
	flag.Parse()

	if *configPath == "" {
		log.Fatal("Usage: redacto --config <config.yaml> -- <command> [args...]")
	}

	args := flag.Args()
	if len(args) == 0 {
		log.Fatal("No command specified. Usage: redacto --config <config.yaml> -- <command> [args...]")
	}

	// Load and validate config
	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("Config error: %v", err)
	}

	// Load eBPF objects
	var objs bpfObjects
	opts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSizeStart: 1 << 24, // 16MB verifier log
		},
	}
	if err := loadBpfObjects(&objs, opts); err != nil {
		log.Fatalf("Loading eBPF objects: %v", err)
	}
	defer objs.Close()

	// Populate pattern maps
	for i, r := range cfg.Rules {
		var entry bpfPatternEntry
		for j := 0; j < len(r.Original); j++ {
			entry.Original[j] = int8(r.Original[j])
		}
		for j := 0; j < len(r.Placeholder); j++ {
			entry.Replacement[j] = int8(r.Placeholder[j])
		}
		entry.Len = uint32(len(r.Original))
		entry.Active = 1

		key := uint32(i)
		if err := objs.Patterns.Put(key, entry); err != nil {
			log.Fatalf("Setting pattern %d: %v", i, err)
		}
	}

	// Set pattern count
	countKey := uint32(0)
	countVal := uint32(len(cfg.Rules))
	if err := objs.PatternCount.Put(countKey, countVal); err != nil {
		log.Fatalf("Setting pattern count: %v", err)
	}

	// Attach tracepoints
	tpEnterRead, err := link.Tracepoint("syscalls", "sys_enter_read", objs.TracepointSysEnterRead, nil)
	if err != nil {
		log.Fatalf("Attaching sys_enter_read: %v", err)
	}
	defer tpEnterRead.Close()

	tpExitRead, err := link.Tracepoint("syscalls", "sys_exit_read", objs.TracepointSysExitRead, nil)
	if err != nil {
		log.Fatalf("Attaching sys_exit_read: %v", err)
	}
	defer tpExitRead.Close()

	tpWrite, err := link.Tracepoint("syscalls", "sys_enter_write", objs.TracepointSysEnterWrite, nil)
	if err != nil {
		log.Fatalf("Attaching sys_enter_write: %v", err)
	}
	defer tpWrite.Close()

	tpFork, err := link.AttachTracing(link.TracingOptions{
		Program: objs.HandleFork,
	})
	if err != nil {
		log.Fatalf("Attaching fork handler: %v", err)
	}
	defer tpFork.Close()

	tpExit, err := link.AttachTracing(link.TracingOptions{
		Program: objs.HandleExit,
	})
	if err != nil {
		log.Fatalf("Attaching exit handler: %v", err)
	}
	defer tpExit.Close()

	// Start child process
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		log.Fatalf("Starting child process: %v", err)
	}

	// Add child PID to target map
	childPID := uint32(cmd.Process.Pid)
	pidVal := uint8(1)
	if err := objs.TargetPidMap.Put(childPID, pidVal); err != nil {
		log.Fatalf("Adding child PID to target map: %v", err)
	}

	// Forward signals to child
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for s := range sig {
			_ = cmd.Process.Signal(s)
		}
	}()

	// Wait for child and propagate exit code
	err = cmd.Wait()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		log.Fatalf("Child process error: %v", err)
	}
}
