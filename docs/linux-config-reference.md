# SecretKeeper Configuration Reference (Linux)

Configuration file location: `/etc/secretkeeper/config.toml`

## Agent Section

```toml
[agent]
# Log level: trace, debug, info, warn, error
log_level = "info"

# Unix socket path for IPC with UI
socket_path = "/var/run/secretkeeper.sock"

# SQLite database for violation history
database_path = "/var/lib/secretkeeper/violations.db"
```

## Monitoring Section

```toml
[monitoring]
# Monitoring mechanism: auto, fanotify
# - auto: Automatically select best available
# - fanotify: Linux fanotify (requires CAP_SYS_ADMIN)
mechanism = "auto"

# Event buffer size
buffer_size = 1000

# Rate limit (events per second, 0 = unlimited)
max_events_per_sec = 100
```

## Enforcement Section

```toml
[enforcement]
# Mode: block, best-effort, monitor
# - block: Deny unauthorized access (requires fanotify)
# - best-effort: SIGSTOP violating processes
# - monitor: Log only, no enforcement
mode = "block"

# Also suspend parent process on violation
suspend_parent = false

# Days to retain violation history (0 = forever)
history_retention_days = 30
```

## Protected Files

Protected files are defined as an array of categories:

```toml
[[protected_files]]
# Unique identifier for this category
id = "ssh_keys"

# Human-readable name
name = "SSH Private Keys"

# File patterns to protect (supports glob)
# Use ~ for home directory
patterns = [
    "~/.ssh/id_*",
    "~/.ssh/*_key",
    "~/.ssh/*.pem"
]

# Processes allowed to access these files
[[protected_files.allow]]
# Match by base name
base = "ssh"
# Restrict to specific effective UIDs
euid = "1000-65533"

[[protected_files.allow]]
# Match by full path
path = "/usr/bin/git"
euid = "1000-65533"

[[protected_files.allow]]
# Match by regex pattern
path_regex = "^/usr/lib/openssh/.*"
```

### Allow Rule Fields

| Field | Type | Description |
|-------|------|-------------|
| `base` | string | Match process by base name (e.g., "ssh") |
| `path` | string | Match process by exact path |
| `path_regex` | string | Match process by regex pattern |
| `uid` | string | Match by real UID (single, range, or comma-separated) |
| `euid` | string | Match by effective UID |
| `ppid` | integer | Match by parent PID (useful for init-spawned processes) |

### UID/EUID Format

```toml
# Single UID
euid = "1000"

# UID range
euid = "1000-65533"

# Multiple UIDs
euid = "0,1000,1001"
```

## Exclusions

### File Pattern Exclusions

Files matching these patterns are never protected:

```toml
excluded_patterns = [
    # Public keys (not sensitive)
    "~/.ssh/*.pub",
    "~/.ssh/known_hosts",
    "~/.ssh/authorized_keys",

    # Certificates (not sensitive)
    "*.crt",
    "*.pem.pub",

    # Lock files
    "*.lock",
    "*.lck",
]
```

### Global Process Exclusions

Processes matching these rules are never flagged:

```toml
[[global_exclusions]]
# Process base name
base = "syncthing"
# Optional: must be spawned by init (PID 1)
ppid = 1

[[global_exclusions]]
# Backup utilities
base = "restic"
path = "/usr/bin/restic"

[[global_exclusions]]
# System services
path_regex = "^/usr/lib/systemd/.*"
```

## Example Configurations

### SSH Keys

```toml
[[protected_files]]
id = "ssh_keys"
name = "SSH Private Keys"
patterns = [
    "~/.ssh/id_*",
    "~/.ssh/*_key",
]

# Allow SSH client
[[protected_files.allow]]
base = "ssh"
euid = "1000-65533"

# Allow SSH agent
[[protected_files.allow]]
base = "ssh-agent"

# Allow Git (for SSH auth)
[[protected_files.allow]]
path = "/usr/bin/git"

# Allow VS Code remote
[[protected_files.allow]]
path_regex = "^/usr/share/code/.*"
```

### AWS Credentials

```toml
[[protected_files]]
id = "aws_credentials"
name = "AWS Credentials"
patterns = [
    "~/.aws/credentials",
    "~/.aws/config",
]

# Allow AWS CLI
[[protected_files.allow]]
base = "aws"

# Allow Terraform
[[protected_files.allow]]
base = "terraform"

# Allow Python (for boto3)
[[protected_files.allow]]
base = "python"
path_regex = "^/usr/bin/python.*"
```

### Browser Passwords (Linux Desktop)

```toml
[[protected_files]]
id = "firefox_passwords"
name = "Firefox Password Store"
patterns = [
    "~/.mozilla/firefox/*/logins.json",
    "~/.mozilla/firefox/*/key*.db",
    "~/.mozilla/firefox/*/cert*.db",
]

# Only Firefox should access
[[protected_files.allow]]
path = "/usr/lib/firefox/firefox"

[[protected_files.allow]]
path = "/snap/firefox/current/usr/lib/firefox/firefox"
```

### GNOME Keyring

```toml
[[protected_files]]
id = "gnome_keyring"
name = "GNOME Keyring"
patterns = [
    "~/.local/share/keyrings/*",
]

# GNOME Keyring daemon
[[protected_files.allow]]
path = "/usr/bin/gnome-keyring-daemon"

# Secret tool
[[protected_files.allow]]
path = "/usr/bin/secret-tool"
```

## Default Protected Categories

The default configuration protects:

- SSH keys and certificates
- GPG/PGP keys
- AWS, GCP, Azure credentials
- Kubernetes configs
- Docker configs
- API tokens (GitHub, GitLab, npm, etc.)
- Database credentials
- Password manager stores
- Browser password databases
- Email credentials
- VPN configurations

See `agent/config/default.toml` for the complete default configuration.

## Reloading Configuration

After editing the configuration, restart the service:

```bash
sudo systemctl restart secretkeeper
```

## Validating Configuration

Check configuration syntax:

```bash
/usr/local/bin/secretkeeper-agent --config /etc/secretkeeper/config.toml check
```
