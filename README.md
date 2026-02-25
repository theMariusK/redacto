# redacto

FUSE-based cross-platform file redaction tool. Mounts a virtual filesystem overlay that mirrors a real project directory, redacting secrets on read and rehydrating them on write.

## Features

- **Cross-platform**: Works on Linux and macOS (no root required)
- **No kernel taint**: Pure userspace, no eBPF
- **All access patterns**: Handles mmap, pread, readv automatically via FUSE
- **Same config format**: Compatible with `redacto` YAML config (`~/.redacto.yaml`)
- **Binary file detection**: Skips binary files by extension and content sniffing
- **Exec mode**: Mount, run a command inside the mount, unmount on exit

## Requirements

- Go 1.22+
- Linux: `libfuse3-dev` (or `fuse3` package)
- macOS: [macFUSE](https://osxfuse.github.io/) or [FUSE-T](https://www.fuse-t.org/)

## Build

```bash
make build
```

## Usage

### Exec mode (recommended for AI agents)

```bash
# Mount, launch agent inside mount, unmount on exit
redacto /home/user/project -- gemini

# Source dir defaults to current directory if omitted
redacto -- gemini

# With explicit config
redacto --config /path/to/redact.yaml /home/user/project -- claude-code
```

The child process runs with its working directory set to the mount point. All file reads return redacted content; writes are rehydrated back to originals.

### Mount-only mode

```bash
# Mount and wait for Ctrl+C
redacto /home/user/project /mnt/redacted

# Source dir defaults to current directory
redacto /mnt/redacted

# With auto temp mount dir
redacto --mount-dir /tmp/mymount /home/user/project
```

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--config PATH` | Config YAML path | `~/.redacto.yaml` |
| `--mount-dir PATH` | Explicit mount point | auto temp dir |
| `--no-rehydrate-writes` | Disable write rehydration | false |
| `--debug` | FUSE debug logging | false |

## Config Format

Same as `redacto` — your existing `~/.redacto.yaml` works:

```yaml
rules:
  - original: "sk-ant-api03-realkey1234567890abcdef"
    placeholder: "sk-ant-api03-XXXXXXXXXXXXXXXXXXXXXXX"
  - original: "password1234"
    placeholder: "************"
  - original: "SecretCorp"
    # placeholder auto-generated (SHA-256 hex, same length)

env_rules:
  - name: "ANTHROPIC_API_KEY"
    placeholder: "REDACTED"

# Optional: additional extensions/paths to skip
skip_extensions: [".bin", ".dat"]
skip_paths: [".cache", "build"]
```

### Constraints

- **Same-length**: `original` and `placeholder` must be the same byte length (auto-generated placeholders satisfy this)
- **No rule count limit**: Unlike the eBPF version, there is no 16-rule or 128-byte limit

## How It Works

```
AI Agent (works in /mnt/redacted)
            |
    reads/writes files
            |
    Kernel VFS (FUSE)
            |
    redacto daemon (Go, userspace)
        |                   |
    Read handler:       Write handler:
    pread(real_fd)      scan for placeholders
    scan & redact       replace with originals
    return redacted     pwrite(real_fd)
        |                   |
    Real Filesystem (/home/user/project)
```

- `direct_io` is enabled to bypass the kernel page cache, ensuring every read/write passes through the redaction handlers
- Binary files are skipped (by extension and null-byte detection)
- `.git`, `node_modules`, and `vendor` directories are skipped by default

## eBPF vs FUSE Comparison

| Aspect | eBPF version | FUSE version |
|--------|-----------------|----------------------|
| Platform | Linux only | Linux + macOS |
| Privileges | Root required | User (fusermount) |
| Transparency | Fully transparent | Agent uses mount path |
| Syscall coverage | read/write only | All (mmap, pread, readv) |
| Kernel taint | Yes | No |
| Build deps | clang, bpftool, vmlinux.h | None (pure Go) |
