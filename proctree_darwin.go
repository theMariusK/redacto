package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// getProcessComm returns the command name for a PID using sysctl kern.proc.pid.
func getProcessComm(pid uint32) string {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", int(pid))
	if err != nil {
		return ""
	}
	return unix.ByteSliceToString(kp.Proc.P_comm[:])
}

// getParentPid returns the parent PID using sysctl kern.proc.pid.
func getParentPid(pid uint32) (uint32, error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", int(pid))
	if err != nil {
		return 0, fmt.Errorf("sysctl kern.proc.pid %d: %w", pid, err)
	}
	return uint32(kp.Eproc.Ppid), nil
}
