package main

import (
	"os"
	"testing"
)

func TestGetParentPid(t *testing.T) {
	pid := uint32(os.Getpid())
	ppid, err := getParentPid(pid)
	if err != nil {
		t.Fatalf("getParentPid(%d): %v", pid, err)
	}
	if ppid == 0 {
		t.Fatalf("expected non-zero parent PID, got 0")
	}
	if ppid != uint32(os.Getppid()) {
		t.Errorf("expected ppid %d, got %d", os.Getppid(), ppid)
	}
}

func TestGetProcessComm(t *testing.T) {
	pid := uint32(os.Getpid())
	comm := getProcessComm(pid)
	if comm == "" {
		t.Fatalf("getProcessComm(%d) returned empty string", pid)
	}
}

func TestGetProcessCommNonexistent(t *testing.T) {
	// PID 0 is the kernel scheduler, /proc/0/comm doesn't exist as a regular file
	comm := getProcessComm(4294967295) // max uint32, extremely unlikely to exist
	if comm != "" {
		t.Errorf("expected empty string for nonexistent PID, got %q", comm)
	}
}

func TestGetParentPidNonexistent(t *testing.T) {
	_, err := getParentPid(4294967295)
	if err == nil {
		t.Fatal("expected error for nonexistent PID, got nil")
	}
}

func TestNilProcessChecker(t *testing.T) {
	var pc *ProcessChecker
	if pc.ShouldPassthrough(1) {
		t.Error("nil ProcessChecker should return false")
	}
}

func TestNewProcessCheckerEmpty(t *testing.T) {
	pc := NewProcessChecker(map[string]bool{})
	if pc != nil {
		t.Error("expected nil ProcessChecker for empty commands")
	}
}

func TestShouldPassthroughNoMatch(t *testing.T) {
	pc := NewProcessChecker(map[string]bool{
		"nonexistent-command-xyz": true,
	})
	pid := uint32(os.Getpid())
	if pc.ShouldPassthrough(pid) {
		t.Error("expected false for non-matching command")
	}
}

func TestShouldPassthroughCachesResult(t *testing.T) {
	pc := NewProcessChecker(map[string]bool{
		"nonexistent-command-xyz": true,
	})
	pid := uint32(os.Getpid())

	// First call populates cache.
	result1 := pc.ShouldPassthrough(pid)
	// Second call should hit cache and return same result.
	result2 := pc.ShouldPassthrough(pid)

	if result1 != result2 {
		t.Errorf("cached result differs: %v vs %v", result1, result2)
	}
}
