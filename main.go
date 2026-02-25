package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type pattern_entry bpf redactor.c

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"gopkg.in/yaml.v3"
)

// generatePlaceholder creates a deterministic same-length placeholder from the
// original string using a SHA-256 hash, encoded as hex. The hash is repeated
// as needed to match the original length.
func generatePlaceholder(original string) string {
	h := sha256.Sum256([]byte(original))
	hexStr := hex.EncodeToString(h[:])
	// Repeat hex string to cover any length up to 128
	for len(hexStr) < len(original) {
		hexStr += hexStr
	}
	return hexStr[:len(original)]
}

type Rule struct {
	Original    string `yaml:"original"`
	Placeholder string `yaml:"placeholder"`
}

type EnvRule struct {
	Name        string `yaml:"name"`
	Placeholder string `yaml:"placeholder"`
}

type Config struct {
	Rules    []Rule    `yaml:"rules"`
	EnvRules []EnvRule `yaml:"env_rules"`
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

	if len(cfg.Rules) == 0 && len(cfg.EnvRules) == 0 {
		return nil, fmt.Errorf("config has no rules")
	}
	if len(cfg.Rules) > 16 {
		return nil, fmt.Errorf("too many rules: %d (max 16)", len(cfg.Rules))
	}

	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		if len(r.Original) == 0 {
			return nil, fmt.Errorf("rule %d: original must be non-empty", i)
		}
		if len(r.Original) > 128 {
			return nil, fmt.Errorf("rule %d: original too long (%d bytes, max 128)", i, len(r.Original))
		}
		if len(r.Placeholder) == 0 {
			r.Placeholder = generatePlaceholder(r.Original)
		}
		if len(r.Placeholder) > 128 {
			return nil, fmt.Errorf("rule %d: placeholder too long (%d bytes, max 128)", i, len(r.Placeholder))
		}
		if len(r.Original) != len(r.Placeholder) {
			return nil, fmt.Errorf("rule %d: original (%d bytes) and placeholder (%d bytes) must be the same length",
				i, len(r.Original), len(r.Placeholder))
		}
	}

	for i, r := range cfg.EnvRules {
		if len(r.Name) == 0 || len(r.Placeholder) == 0 {
			return nil, fmt.Errorf("env_rule %d: name and placeholder must be non-empty", i)
		}
	}

	return &cfg, nil
}

func main() {
	configPath := flag.String("config", "", "Path to redaction config YAML file (default: ~/.redacto.yaml)")
	noRehydrateWrites := flag.Bool("no-rehydrate-writes", false, "Disable rehydrating placeholders back to originals on write syscalls")
	projectDir := flag.String("project-dir", "", "Only redact reads from files under this directory (default: current working directory)")
	runAsUser := flag.String("user", "", "Run the child process as this user (default: $SUDO_USER)")
	flag.Parse()

	// Default --user to the user who invoked sudo
	if *runAsUser == "" {
		if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
			*runAsUser = sudoUser
		}
	}

	// Default --project-dir to current working directory
	if *projectDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			log.Fatalf("Cannot determine working directory: %v", err)
		}
		*projectDir = wd
	}

	// Resolve config path: explicit flag > ~/.redacto.yaml
	if *configPath == "" {
		var home string
		if *runAsUser != "" {
			u, err := user.Lookup(*runAsUser)
			if err != nil {
				log.Fatalf("Looking up user %q for config path: %v", *runAsUser, err)
			}
			home = u.HomeDir
		} else {
			var err error
			home, err = os.UserHomeDir()
			if err != nil {
				log.Fatalf("Cannot determine home directory: %v", err)
			}
		}
		defaultPath := home + "/.redacto.yaml"
		if _, err := os.Stat(defaultPath); err == nil {
			*configPath = defaultPath
		} else {
			log.Fatalf("No config specified and %s not found. Usage: redacto [--config <config.yaml>] -- <command> [args...]", defaultPath)
		}
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

	// Two-step BPF load: get spec, set variables, then load
	spec, err := loadBpf()
	if err != nil {
		log.Fatalf("Loading BPF spec: %v", err)
	}

	if !*noRehydrateWrites {
		if err := spec.Variables["rehydrate_writes"].Set(uint32(1)); err != nil {
			log.Fatalf("Setting rehydrate_writes: %v", err)
		}
	}

	if *projectDir != "" {
		fi, err := os.Stat(*projectDir)
		if err != nil {
			log.Fatalf("Stat project-dir %q: %v", *projectDir, err)
		}
		if !fi.IsDir() {
			log.Fatalf("--project-dir %q is not a directory", *projectDir)
		}
		stat, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			log.Fatal("Failed to get syscall.Stat_t from os.Stat (unsupported platform?)")
		}
		// Convert userspace dev_t (new_encode_dev format) to kernel-internal
		// MKDEV format. Userspace: (minor&0xff) | (major<<8) | ((minor&~0xff)<<12)
		// Kernel: (major<<20) | minor
		major := (stat.Dev & 0xfff00) >> 8
		minor := (stat.Dev & 0xff) | ((stat.Dev >> 12) & 0xfff00)
		kernelDev := (major << 20) | minor
		if err := spec.Variables["project_dev"].Set(kernelDev); err != nil {
			log.Fatalf("Setting project_dev: %v", err)
		}
		if err := spec.Variables["project_ino"].Set(stat.Ino); err != nil {
			log.Fatalf("Setting project_ino: %v", err)
		}
		log.Printf("Project-dir filtering enabled: %s (dev=%d, ino=%d, kernelDev=%d)", *projectDir, stat.Dev, stat.Ino, kernelDev)
	}

	var objs bpfObjects
	opts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSizeStart: 1 << 24, // 16MB verifier log
		},
	}
	if err := spec.LoadAndAssign(&objs, opts); err != nil {
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

	// Attach write tracepoint unless rehydration is disabled
	if !*noRehydrateWrites {
		tpWrite, err := link.Tracepoint("syscalls", "sys_enter_write", objs.TracepointSysEnterWrite, nil)
		if err != nil {
			log.Fatalf("Attaching sys_enter_write: %v", err)
		}
		defer tpWrite.Close()
	}

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

	// Drop privileges for child process if --user is set
	if *runAsUser != "" {
		u, err := user.Lookup(*runAsUser)
		if err != nil {
			log.Fatalf("Looking up user %q: %v", *runAsUser, err)
		}
		uid, err := strconv.ParseUint(u.Uid, 10, 32)
		if err != nil {
			log.Fatalf("Parsing UID %q: %v", u.Uid, err)
		}
		gid, err := strconv.ParseUint(u.Gid, 10, 32)
		if err != nil {
			log.Fatalf("Parsing GID %q: %v", u.Gid, err)
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{
				Uid: uint32(uid),
				Gid: uint32(gid),
			},
		}
		cmd.Env = append(os.Environ(),
			"HOME="+u.HomeDir,
			"USER="+u.Username,
		)
		log.Printf("Child process will run as user %s (uid=%d, gid=%d)", u.Username, uid, gid)
	}

	// Apply env var redaction
	env := cmd.Env
	if env == nil {
		env = os.Environ()
	}
	if len(cfg.EnvRules) > 0 {
		for i, e := range env {
			for _, rule := range cfg.EnvRules {
				prefix := rule.Name + "="
				if strings.HasPrefix(e, prefix) {
					env[i] = prefix + rule.Placeholder
					break
				}
			}
		}
	}
	cmd.Env = env

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
