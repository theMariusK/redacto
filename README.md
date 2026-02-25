# redacto

FUSE-based cross-platform file redaction tool. Mounts a virtual filesystem overlay that mirrors a real project directory, redacting secrets on read and rehydrating them on write.

## Requirements

- Go 1.22+
- Linux: `libfuse3-dev` (or `fuse3` package)
- macOS: [macFUSE](https://osxfuse.github.io/) or [FUSE-T](https://www.fuse-t.org/)

## Build

```bash
make
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

Default config lives at `~/.redacto.yaml`:

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
