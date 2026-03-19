package main

import "sync"

// ProcessChecker determines whether a calling process should bypass redaction
// by walking its ancestry and checking command names against a configured
// passthrough list. Platform-specific helpers (getParentPid, getProcessComm)
// are in proctree_linux.go and proctree_darwin.go.
type ProcessChecker struct {
	commands map[string]bool // passthrough command names
	cache    sync.Map        // pid (uint32) → passthrough (bool)
}

// NewProcessChecker creates a ProcessChecker from a set of command names.
// Returns nil if the set is empty.
func NewProcessChecker(commands map[string]bool) *ProcessChecker {
	if len(commands) == 0 {
		return nil
	}
	return &ProcessChecker{commands: commands}
}

// ShouldPassthrough returns true if the given PID (or any of its ancestors)
// matches a configured passthrough command. Safe to call on a nil receiver.
func (pc *ProcessChecker) ShouldPassthrough(pid uint32) bool {
	if pc == nil {
		return false
	}

	// Check cache first.
	if v, ok := pc.cache.Load(pid); ok {
		return v.(bool)
	}

	result := pc.walk(pid)
	pc.cache.Store(pid, result)
	return result
}

func (pc *ProcessChecker) walk(pid uint32) bool {
	current := pid
	visited := make(map[uint32]bool) // cycle protection
	for current > 1 {
		if visited[current] {
			break
		}
		visited[current] = true

		comm := getProcessComm(current)
		if pc.commands[comm] {
			return true
		}

		ppid, err := getParentPid(current)
		if err != nil || ppid == current {
			break
		}
		current = ppid
	}
	return false
}
