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

When using redacto with AI agents that support session resume (e.g. `gemini --resume`), two flags are important:

### `--mount-dir` (required for resume)

By default redacto creates a temporary mount directory like `/tmp/redacto-abc123`. The agent's working directory is set to this mount point. On restart, a new temp dir is created, so the agent cannot find its previous session — most agents identify sessions by the directory they were started in.

Use `--mount-dir` to set a stable mount point:

```bash
redacto --mount-dir ~/redacto-mount -- gemini --resume
```

This ensures the agent always starts in the same directory and can locate previous sessions.

### `--mappings-file` (needed for regex rules)

Whether you need `--mappings-file` depends on which rule types you use:

- **Literal rules only** — `--mappings-file` is not needed. The original/placeholder pairs are defined in your config, so rehydration works without any persisted state.
- **Regex rules** — `--mappings-file` is needed. Regex matches are discovered at runtime and the placeholder-to-original mappings are stored in memory. Without persistence, a restarted redacto cannot rehydrate placeholders from the previous session — the agent writes a hex placeholder to disk instead of the original secret, corrupting the file.

### Recommended setup for session resume

```bash
redacto \
  --mount-dir ~/redacto-mount \
  --mappings-file ~/.redacto-mappings.json \
  -- gemini --resume
```

On shutdown, mappings are saved to the file. On startup, they are loaded back, giving full session continuity.

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
| `--mappings-file PATH` | Persist regex mappings to this file for cross-session rehydration | (none, opt-in) |
| `--debug` | FUSE debug logging | false |

## Config Format

Default config lives at `~/.redacto.yaml`:

```yaml
rules:
  # Literal rules — exact string match
  - original: "sk-ant-api03-realkey1234567890abcdef"
    placeholder: "sk-ant-api03-XXXXXXXXXXXXXXXXXXXXXXX"
  - original: "password1234"
    placeholder: "************"
  - original: "SecretCorp"
    # placeholder auto-generated (SHA-256 hex, same length)

  # Regex rules — match by pattern, placeholder auto-generated per match
  - pattern: "ghp_[A-Za-z0-9]{36}"            # GitHub personal access tokens
  - pattern: "sk-ant-api03-[A-Za-z0-9]{24}"   # Anthropic API keys
  - pattern: "AKIA[0-9A-Z]{16}"               # AWS access key IDs
  - pattern: "[A-Fa-f0-9]{40}"                # 40-char hex strings (SHA-1, tokens)

env_rules:
  - name: "ANTHROPIC_API_KEY"
    placeholder: "REDACTED"

# Optional: additional extensions/paths to skip
skip_extensions: [".bin", ".dat"]
skip_paths: [".cache", "build"]
```

### Rule types

Each rule must have exactly one of `original` or `pattern`.

**Literal rules** (`original`):
- Exact string match
- `placeholder` is optional — if omitted, a deterministic same-length hex string is auto-generated
- If specified, `original` and `placeholder` must be the same byte length

**Regex rules** (`pattern`):
- Uses [Go regex syntax](https://pkg.go.dev/regexp/syntax)
- `placeholder` is ignored — a deterministic same-length placeholder is auto-generated per match
- Matched text is stored for rehydration (mappings accumulate for the scanner's lifetime)
- Use `--mappings-file` to persist these mappings across restarts, so placeholders from a previous session can still be rehydrated

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
