package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// getProcessComm reads the command name for a PID from /proc/[pid]/comm.
func getProcessComm(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// getParentPid reads the parent PID from /proc/[pid]/stat.
// The stat format is: pid (comm) state ppid ...
// comm can contain spaces and parentheses, so we find the last ')'.
func getParentPid(pid uint32) (uint32, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	s := string(data)
	closeIdx := strings.LastIndex(s, ")")
	if closeIdx < 0 || closeIdx+2 >= len(s) {
		return 0, fmt.Errorf("malformed /proc/%d/stat", pid)
	}
	fields := strings.Fields(s[closeIdx+2:])
	if len(fields) < 2 {
		return 0, fmt.Errorf("not enough fields in /proc/%d/stat", pid)
	}
	// fields[0] = state, fields[1] = ppid
	ppid, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parsing ppid from /proc/%d/stat: %w", pid, err)
	}
	return uint32(ppid), nil
}
