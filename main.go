package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fuse"
)

func main() {
	configPath := flag.String("config", "", "Path to redaction config YAML (default: ~/.redacto.yaml)")
	mountDir := flag.String("mount-dir", "", "Explicit mount point (default: auto temp dir)")
	noRehydrateWrites := flag.Bool("no-rehydrate-writes", false, "Disable write rehydration")
	debug := flag.Bool("debug", false, "Enable FUSE debug logging")
	flag.Parse()

	args := flag.Args()

	// Determine source dir and child command.
	// Usage: redacto [flags] <source-dir> [-- command args...]
	// or:   redacto [flags] <source-dir> <mount-dir>
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: redacto [flags] <source-dir> [-- command args...]\n")
		fmt.Fprintf(os.Stderr, "       redacto [flags] <source-dir> <mount-dir>\n")
		os.Exit(1)
	}

	sourceDir := args[0]

	// Validate source directory.
	fi, err := os.Stat(sourceDir)
	if err != nil {
		log.Fatalf("Source directory %q: %v", sourceDir, err)
	}
	if !fi.IsDir() {
		log.Fatalf("Source %q is not a directory", sourceDir)
	}

	// Determine mode: exec mode (has --) or mount-only mode.
	var childArgs []string
	execMode := false

	// Check if there's a "--" separator in os.Args to detect exec mode.
	for i, a := range os.Args {
		if a == "--" && i+1 < len(os.Args) {
			childArgs = os.Args[i+1:]
			execMode = true
			break
		}
	}

	// If not exec mode, check for second positional arg as mount dir.
	if !execMode && len(args) >= 2 {
		*mountDir = args[1]
	}

	// Resolve config path.
	if *configPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("Cannot determine home directory: %v", err)
		}
		defaultPath := home + "/.redacto.yaml"
		if _, err := os.Stat(defaultPath); err == nil {
			*configPath = defaultPath
		} else {
			log.Fatalf("No config specified and %s not found", defaultPath)
		}
	}

	// Load config.
	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("Config error: %v", err)
	}

	scanner := NewScanner(cfg.Rules)

	// Build skip extension set.
	skipExts := make(map[string]bool)
	for k, v := range defaultSkipExtensions {
		skipExts[k] = v
	}
	for _, ext := range cfg.SkipExtensions {
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		skipExts[strings.ToLower(ext)] = true
	}

	// Build skip paths set.
	skipPaths := map[string]bool{
		".git":         true,
		"node_modules": true,
		"vendor":       true,
	}
	for _, p := range cfg.SkipPaths {
		skipPaths[p] = true
	}

	rr := &RedactRoot{
		scanner:        scanner,
		skipExtensions: skipExts,
		skipPaths:      skipPaths,
		rehydrate:      !*noRehydrateWrites,
	}

	// Create or use mount directory.
	tempMount := false
	if *mountDir == "" {
		dir, err := os.MkdirTemp("", "redacto-*")
		if err != nil {
			log.Fatalf("Creating temp mount dir: %v", err)
		}
		*mountDir = dir
		tempMount = true
	} else {
		if err := os.MkdirAll(*mountDir, 0755); err != nil {
			log.Fatalf("Creating mount dir %q: %v", *mountDir, err)
		}
	}

	// Mount the FUSE filesystem.
	server, err := newRedactFS(sourceDir, *mountDir, rr, *debug)
	if err != nil {
		if tempMount {
			os.Remove(*mountDir)
		}
		log.Fatalf("Mount failed: %v", err)
	}

	log.Printf("Mounted %s -> %s", sourceDir, *mountDir)

	cleanup := func() {
		log.Printf("Unmounting %s", *mountDir)
		server.Unmount()
		if tempMount {
			os.Remove(*mountDir)
		}
	}

	if execMode {
		runExecMode(childArgs, *mountDir, cfg, cleanup)
	} else {
		runMountMode(server, cleanup)
	}
}

func runExecMode(childArgs []string, mountDir string, cfg *Config, cleanup func()) {
	defer cleanup()

	cmd := exec.Command(childArgs[0], childArgs[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Dir = mountDir

	// Build environment with env_rules applied.
	env := os.Environ()
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

	// Forward signals to child.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for s := range sig {
			_ = cmd.Process.Signal(s)
		}
	}()

	// Wait for child and propagate exit code.
	err := cmd.Wait()
	signal.Stop(sig)
	close(sig)

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		log.Fatalf("Child process error: %v", err)
	}
}

func runMountMode(server *fuse.Server, cleanup func()) {
	// Wait for Ctrl+C, then unmount.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	log.Println("Press Ctrl+C to unmount")

	<-sig
	signal.Stop(sig)
	cleanup()
}
