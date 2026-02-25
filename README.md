# redacto

eBPF-based transparent string redaction tool. Wraps a child process and intercepts its `read`/`write` syscalls to redact sensitive strings on the read path and rehydrate them on the write path, based on a YAML config.

The child process sees redacted data; files on disk remain unchanged.

## How it works

```
redact.yaml --> Go orchestrator --> Launch child (e.g. cat secret.txt)
                     |
                     +-- Populates BPF pattern map
                     +-- Populates PID target map
                     +-- Attaches eBPF programs:
                         sys_enter_read  -> store buf pointer
                         sys_exit_read   -> scan & redact (original -> placeholder)
                         sys_enter_write -> scan & rehydrate (placeholder -> original, fd>2 only)
                         sched_process_fork -> track child PIDs
                         sched_process_exit -> cleanup PIDs
```

- **Read path**: kernel fills buffer, eBPF scans for sensitive strings, overwrites with placeholders via `bpf_probe_write_user`. The child sees redacted data.
- **Write path** (fd > 2): child writes buffer, eBPF scans for placeholders, overwrites with originals. Files on disk get clean data.
- **stdout/stderr** (fd 0-2): write hook skips them, so terminal output stays redacted.

## Requirements

- Linux kernel >= 5.17 (uses `bpf_loop` helper)
- Go 1.24+
- `bpftool`, `clang`, `llvm` (for eBPF compilation)
- Root privileges (eBPF + `bpf_probe_write_user`)

## Build

```bash
make
```

This will:
1. Generate `vmlinux.h` from kernel BTF
2. Compile `redactor.c` via `bpf2go`
3. Build the `redacto` binary

## Configuration

Create a YAML config file with redaction rules:

```yaml
rules:
  - original: "SecretCorp"
    placeholder: "REDACTED_1"
  - original: "api_key_12345"
    placeholder: "XXXXXXXXXXXXX"
  - original: "password1234"
    placeholder: "************"
```

Constraints:
- Original and placeholder must be the **same length**
- Max 16 bytes per pattern
- Max 8 rules

## Usage

```bash
# Basic: redact output of a command
sudo ./redacto --config redact.yaml -- cat /tmp/secret.txt

# Wrap an interactive shell (all child processes are tracked)
sudo ./redacto --config redact.yaml -- bash

# Wrap a file copy (write rehydration preserves originals on disk)
sudo ./redacto --config redact.yaml -- cp /tmp/secret.txt /tmp/copy.txt
```

## Example

```bash
$ echo "The company SecretCorp has api_key_12345 access" > /tmp/test.txt

$ sudo ./redacto --config redact.yaml -- cat /tmp/test.txt
The company REDACTED_1 has XXXXXXXXXXXXX access

$ cat /tmp/test.txt
The company SecretCorp has api_key_12345 access
```

## Limitations

- Max 4096 bytes scanned per syscall
- Patterns spanning two successive `read()` calls won't be detected
- Only hooks `read`/`write` (not `readv`/`writev`/`pread64`/`mmap`)
- `bpf_probe_write_user` taints the kernel (prints warning to dmesg)
- Write rehydration modifies the userspace buffer (acceptable for single-use buffers like `cat`/`cp`)
