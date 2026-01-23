# SecretKeeper

SecretKeeper is a security daemon that prevents credential exfiltration by monitoring access to sensitive files such as SSH keys, API tokens, and cloud provider credentials.

## Purpose

Protect users from supply-chain attacks and malicious software that attempt to steal secrets stored on disk. When an unauthorized process attempts to read a protected file, SecretKeeper logs the violation and can optionally block the access.

## Platform Support

| Platform | Mechanism | Blocking | Minimum Version |
|----------|-----------|----------|-----------------|
| macOS | Endpoint Security Framework | True blocking | 13.0+ |
| Linux | fanotify (FAN_OPEN_PERM) | True blocking | Kernel 5.1+ |
| FreeBSD | DTrace | Best-effort | 10+ |
| NetBSD | DTrace | Best-effort | 8+ |

## Architecture

```
secretkeeper-agent (privileged daemon)
    ├── File access monitor (ESF/fanotify/DTrace)
    ├── Rule engine with process verification
    └── SQLite database for violation logging

SecretKeeper UI (unprivileged)
    └── Displays violations and manages exceptions via Unix socket IPC
```

## Protected File Categories

- SSH keys and certificates
- GPG/PGP private keys
- AWS, GCP, Azure credentials
- Kubernetes and Docker configs
- Package manager tokens (npm, PyPI, RubyGems)
- Browser password stores
- Password manager databases
- Shell history files

## Quick Start

### macOS

```bash
# Using Homebrew (coming soon)
brew install secretkeeper

# Or build from source
make build-release
sudo make install-macos
```

### Linux

```bash
# Debian/Ubuntu
wget https://github.com/secretkeeper/secretkeeper/releases/latest/download/secretkeeper_amd64.deb
sudo dpkg -i secretkeeper_amd64.deb

# RHEL/Fedora
wget https://github.com/secretkeeper/secretkeeper/releases/latest/download/secretkeeper.x86_64.rpm
sudo dnf install ./secretkeeper.x86_64.rpm

# Or build from source
make build-release
sudo make install-linux
```

### FreeBSD

```bash
make build-release
sudo make install-freebsd
```

### NetBSD

```bash
make build-release
sudo make install-netbsd
```

## Requirements

### macOS
- macOS 13.0+
- Endpoint Security entitlement (for production builds)
- Full Disk Access (for monitoring user directories)

### Linux
- Kernel 5.1+ (for FAN_OPEN_PERM support)
- CAP_SYS_ADMIN capability (configured via systemd)
- systemd for service management

### FreeBSD
- FreeBSD 10+
- DTrace enabled

### NetBSD
- NetBSD 8+
- DTrace enabled (MKDTRACE=yes in build)
- Root privileges

## Documentation

- [Linux Installation Guide](docs/linux-installation.md)
- [Linux Configuration Reference](docs/linux-config-reference.md)

## How It Works

### macOS (Endpoint Security Framework)

SecretKeeper subscribes to `ES_EVENT_TYPE_AUTH_OPEN` events to monitor file access attempts. When an open event targets a protected path pattern (e.g., `~/.ssh/id_*`, `~/.aws/credentials`), the agent evaluates the requesting process against a whitelist of allowed applications.

**Decision logic:**
- Allow if the process matches a configured rule (path, code signature, team ID)
- Deny and log if no rule matches

### Linux (fanotify)

SecretKeeper uses the fanotify API with `FAN_OPEN_PERM` permission events for true pre-access blocking. When a process attempts to open a protected file, the kernel blocks the operation until SecretKeeper responds with allow or deny.

**Decision logic:**
- Allow if the process matches a configured rule (path, UID, EUID)
- Deny and log if no rule matches
- Optionally SIGSTOP violating processes

### FreeBSD (DTrace)

SecretKeeper uses DTrace to monitor file access system calls. While it cannot block access before it occurs, it can detect violations and suspend offending processes.

### NetBSD (DTrace)

Like FreeBSD, SecretKeeper uses DTrace on NetBSD to monitor `open` and `openat` system calls. NetBSD has included DTrace support since version 8. Process executable lookup uses `/proc/<pid>/exe` (when procfs is mounted) or `sysctl kern.proc.pathname`.

## Building

```bash
# Build all components
make build-release

# Build agent only
make build-agent

# Run tests
make test

# Run linter
make lint
```

## License

MIT
