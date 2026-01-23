# SecretKeeper

SecretKeeper is a macOS security daemon that prevents credential exfiltration by monitoring access to sensitive files such as SSH keys, API tokens, and cloud provider credentials.

## Purpose

Protect users from supply-chain attacks and malicious software that attempt to steal secrets stored on disk. When an unauthorized process attempts to read a protected file, SecretKeeper logs the violation and can optionally block the access.

## Endpoint Security Framework Usage

SecretKeeper subscribes to `ES_EVENT_TYPE_AUTH_OPEN` events to monitor file access attempts. When an open event targets a protected path pattern (e.g., `~/.ssh/id_*`, `~/.aws/credentials`), the agent evaluates the requesting process against a whitelist of allowed applications.

**Events subscribed:**
- `ES_EVENT_TYPE_AUTH_OPEN` — intercept file open attempts on protected paths

**Decision logic:**
- Allow if the process matches a configured rule (path, code signature, team ID)
- Deny and log if no rule matches

## Architecture

```
secretkeeper-agent (privileged daemon)
    ├── Endpoint Security client for file access events
    ├── Rule engine with code signature verification
    └── SQLite database for violation logging

SecretKeeper.app (unprivileged UI)
    └── Displays violations and manages exceptions via Unix socket IPC
```

## Protected File Categories

- SSH keys and known hosts
- GPG/PGP private keys
- AWS, GCP, Azure credentials
- Kubernetes and Docker configs
- Package manager tokens (npm, PyPI, RubyGems)
- Shell history files

## Requirements

- macOS 13.0+
- Endpoint Security entitlement
- Full Disk Access (for monitoring user directories)
