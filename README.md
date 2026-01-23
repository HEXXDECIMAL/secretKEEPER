# SecretKeeper

> **Preview Release** - API and configuration format may change.

Security daemon that prevents credential exfiltration by monitoring access to sensitive files (SSH keys, API tokens, cloud credentials). Blocks unauthorized access in real-time on supported platforms.

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

## Requirements

| Platform | Requirements |
|----------|--------------|
| macOS | 13.0+, Endpoint Security entitlement, Full Disk Access |
| Linux | Kernel 5.1+, CAP_SYS_ADMIN, systemd |
| FreeBSD | 10+, DTrace enabled |
| NetBSD | 8+, DTrace enabled (MKDTRACE=yes) |

## How It Works

- **macOS**: Subscribes to ESF `ES_EVENT_TYPE_AUTH_OPEN` events for pre-access blocking. Evaluates process against whitelist (path, code signature, team ID).
- **Linux**: Uses fanotify `FAN_OPEN_PERM` for kernel-level blocking. Evaluates by path, UID, EUID. Can SIGSTOP violators.
- **FreeBSD/NetBSD**: DTrace monitors `open`/`openat` syscalls. Best-effort detection with process suspension (cannot block before access).

## Building

```bash
make build-release
sudo make install-macos    # macOS
sudo make install-linux    # Linux
sudo make install-freebsd  # FreeBSD
sudo make install-netbsd   # NetBSD

make test                  # Run tests
make lint                  # Run linter
```

## License

MIT
