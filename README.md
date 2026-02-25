# redacto

eBPF-based transparent string redaction tool. Wraps a child process and intercepts its `read` syscalls to redact sensitive strings, based on a YAML config. Rehydrates placeholders back to originals on the write path by default, so files on disk remain unchanged.

The child process sees redacted data; files on disk remain unchanged.

## How it works

```
redact.yaml --> Go orchestrator --> Launch child (e.g. cat secret.txt)
                     |
                     +-- Populates BPF pattern map
                     +-- Populates PID target map
                     +-- Redacts env vars (userspace)
                     +-- Attaches eBPF programs:
                         sys_enter_read  -> store buf pointer
                         sys_exit_read   -> scan & redact (original -> placeholder)
                         sys_enter_write -> scan & rehydrate (unless --no-rehydrate-writes)
                         sched_process_fork -> track child PIDs
                         sched_process_exit -> cleanup PIDs
```

- **Read path**: kernel fills buffer, eBPF scans for sensitive strings, overwrites with placeholders via `bpf_probe_write_user`. The child sees redacted data.
- **Write path** (fd > 2, on by default): eBPF scans write buffers for placeholders and overwrites with originals, so files on disk keep clean data. When `--project-dir` is set, writes to any file under the project directory are rehydrated; without it, only writes to fds that previously had redacted reads are rehydrated. Disable with `--no-rehydrate-writes`.
- **stdout/stderr** (fd 0-2): write hook skips them, so terminal output stays redacted.
- **Env vars**: replaced in userspace before the child process starts. No same-length constraint.

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

Create a YAML config file. By default, `redacto` looks for `~/.redacto.yaml`. Override with `--config`.

```yaml
rules:
  # Placeholder is optional — if omitted, a deterministic hash is auto-generated
  - original: "sk-ant-api03-realkey1234567890abcdef"
  - original: "password1234"
  # You can still specify an explicit placeholder if you prefer
  - original: "SecretCorp"
    placeholder: "REDACT_001"

env_rules:
  - name: "ANTHROPIC_API_KEY"
    placeholder: "REDACTED"
  - name: "AWS_SECRET_ACCESS_KEY"
    placeholder: "REDACTED"
```

### BPF rules (`rules`)

These intercept `read()` syscalls via eBPF to redact data in-flight.

- `placeholder` is **optional**. If omitted, a deterministic same-length hex string is generated from a SHA-256 hash of the original. This means you only need to list the strings to redact.
- If specified, original and placeholder must be the **same length**
- Max 128 bytes per pattern
- Max 16 rules

### Environment rules (`env_rules`)

These replace environment variable values in userspace before the child process starts. Useful for secrets passed via env vars (e.g. API keys), which are read from the process stack and never go through `read()`.

- No same-length constraint (userspace replacement)
- No limit on number of env rules

## Usage

```bash
# Basic: redact output of a command
sudo ./redacto --config redact.yaml -- cat /tmp/secret.txt

# Wrap an interactive shell (all child processes are tracked)
sudo ./redacto --config redact.yaml -- bash

# File copy (rehydration is on by default, copy contains original content)
sudo ./redacto --config redact.yaml -- cp /tmp/secret.txt /tmp/copy.txt

# File copy without rehydration (copy contains redacted content)
sudo ./redacto --config redact.yaml --no-rehydrate-writes -- cp /tmp/secret.txt /tmp/copy.txt

# Only redact files under a specific project directory
# Files outside the project dir pass through untouched
sudo ./redacto --config redact.yaml --project-dir /home/user/project -- cat /home/user/project/secret.txt
# Output: redacted

sudo ./redacto --config redact.yaml --project-dir /home/user/project -- cat /tmp/outside.txt
# Output: NOT redacted (file is outside project dir)

# Run an AI agent with redaction — drop privileges so the agent runs as your user
sudo ./redacto --config redact.yaml --project-dir /home/user/project --user myuser -- gemini

# Env var redaction
ANTHROPIC_API_KEY=sk-real sudo ./redacto --config redact.yaml -- printenv ANTHROPIC_API_KEY
# Output: REDACTED
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `~/.redacto.yaml` | Path to redaction config YAML file. Falls back to `~/.redacto.yaml` if not specified. |
| `--no-rehydrate-writes` | `false` | Disable rehydrating placeholders back to originals on write syscalls (fd > 2). Rehydration is on by default. |
| `--project-dir` | current directory | Only redact reads from files under this directory. |
| `--user` | `$SUDO_USER` | Run the child process as this user. Defaults to the user who invoked `sudo`, so the child finds its config/auth files under the correct `$HOME`. |

## Example

```bash
$ echo "The company has sk-ant-api03-realkey1234567890abcdef access" > /tmp/test.txt

$ sudo ./redacto --config redact.yaml -- cat /tmp/test.txt
The company has sk-ant-api03-XXXXXXXXXXXXXXXXXXXXXXX access

$ cat /tmp/test.txt
The company has sk-ant-api03-realkey1234567890abcdef access
```

## Limitations

- Max 4096 bytes scanned per syscall
- Patterns spanning two successive `read()` calls won't be detected
- Only hooks `read`/`write` (not `readv`/`writev`/`pread64`/`mmap`)
- `bpf_probe_write_user` taints the kernel (prints warning to dmesg)
- Write rehydration (when enabled) modifies the userspace buffer (acceptable for single-use buffers like `cat`/`cp`)
