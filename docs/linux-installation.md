# SecretKeeper Linux Installation Guide

SecretKeeper is a secret exfiltration prevention daemon that monitors and protects sensitive files from unauthorized access.

## Prerequisites

### Kernel Requirements

SecretKeeper requires Linux kernel **5.1 or later** for full fanotify permission event support (`FAN_OPEN_PERM`).

Check your kernel version:
```bash
uname -r
```

### Capability Requirements

The agent requires `CAP_SYS_ADMIN` capability for fanotify file access monitoring. This is automatically configured when using the systemd service.

### Supported Distributions

- Debian 11+ (Bullseye)
- Ubuntu 20.04+ (Focal)
- Fedora 35+
- RHEL/CentOS/Rocky Linux 8+
- Any distribution with kernel 5.1+ and systemd

## Installation Methods

### 1. Package Installation (Recommended)

#### Debian/Ubuntu

```bash
# Download the package
wget https://github.com/secretkeeper/secretkeeper/releases/latest/download/secretkeeper_amd64.deb

# Install
sudo dpkg -i secretkeeper_amd64.deb

# If there are dependency issues
sudo apt-get install -f
```

#### RHEL/Fedora/Rocky Linux

```bash
# Download the package
wget https://github.com/secretkeeper/secretkeeper/releases/latest/download/secretkeeper.x86_64.rpm

# Install (Fedora/RHEL 8+)
sudo dnf install ./secretkeeper.x86_64.rpm

# Or for older systems
sudo rpm -i secretkeeper.x86_64.rpm
```

### 2. Manual Installation

```bash
# Clone repository
git clone https://github.com/secretkeeper/secretkeeper.git
cd secretkeeper

# Build (requires Rust 1.70+)
cargo build --release --package secretkeeper-agent

# Install using Makefile
sudo make install-linux
```

### 3. Building from Source

```bash
# Install Rust if needed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Clone and build
git clone https://github.com/secretkeeper/secretkeeper.git
cd secretkeeper
cargo build --release --package secretkeeper-agent

# Manual installation
sudo install -m 755 target/release/secretkeeper-agent /usr/local/bin/
sudo mkdir -p /etc/secretkeeper /var/lib/secretkeeper
sudo cp agent/config/default.toml /etc/secretkeeper/config.toml
sudo cp install/linux/secretkeeper.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now secretkeeper
```

## Post-Installation

### Verify Installation

```bash
# Check service status
sudo systemctl status secretkeeper

# View logs
sudo journalctl -u secretkeeper -f

# Test IPC connection
echo '{"action":"ping"}' | nc -U /var/run/secretkeeper.sock
```

### Installation Paths

| Component | Path |
|-----------|------|
| Binary | `/usr/local/bin/secretkeeper-agent` |
| Config | `/etc/secretkeeper/config.toml` |
| Data | `/var/lib/secretkeeper/` |
| Socket | `/var/run/secretkeeper.sock` |
| Service | `/etc/systemd/system/secretkeeper.service` |

## Configuration

Edit `/etc/secretkeeper/config.toml` to customize protection rules.

See [linux-config-reference.md](linux-config-reference.md) for detailed configuration options.

After changing configuration, restart the service:
```bash
sudo systemctl restart secretkeeper
```

## Security Hardening

### AppArmor (Ubuntu/Debian)

```bash
# Install profile
sudo cp install/linux/apparmor/usr.local.bin.secretkeeper-agent /etc/apparmor.d/

# Load profile
sudo apparmor_parser -r /etc/apparmor.d/usr.local.bin.secretkeeper-agent

# Verify
sudo aa-status | grep secretkeeper
```

### SELinux (RHEL/Fedora)

```bash
# Build and install policy module
cd install/linux/selinux
make -f /usr/share/selinux/devel/Makefile secretkeeper.pp
sudo semodule -i secretkeeper.pp

# Apply file contexts
sudo restorecon -Rv /usr/local/bin/secretkeeper-agent
sudo restorecon -Rv /etc/secretkeeper
sudo restorecon -Rv /var/lib/secretkeeper

# Verify
sudo semanage fcontext -l | grep secretkeeper
```

## Troubleshooting

### Service Won't Start

1. **Check logs:**
   ```bash
   sudo journalctl -u secretkeeper -n 50 --no-pager
   ```

2. **Verify binary exists:**
   ```bash
   ls -la /usr/local/bin/secretkeeper-agent
   ```

3. **Check config syntax:**
   ```bash
   /usr/local/bin/secretkeeper-agent --config /etc/secretkeeper/config.toml check
   ```

### "fanotify_init failed: Operation not permitted"

The agent requires `CAP_SYS_ADMIN` capability. Ensure you're running via systemd or with sudo.

```bash
# Verify capabilities in service
sudo systemctl show secretkeeper | grep -i capability
```

### No Events Received

1. **Check fanotify limits:**
   ```bash
   cat /proc/sys/fs/fanotify/max_user_marks
   ```

2. **Increase if needed:**
   ```bash
   echo 1048576 | sudo tee /proc/sys/fs/fanotify/max_user_marks
   ```

3. **Make permanent** (add to `/etc/sysctl.d/99-secretkeeper.conf`):
   ```
   fs.fanotify.max_user_marks = 1048576
   ```

### SELinux Denials

Check audit log:
```bash
sudo ausearch -m AVC -ts recent | audit2allow
```

If needed, generate and install additional policy:
```bash
sudo ausearch -m AVC -ts recent | audit2allow -M secretkeeper_local
sudo semodule -i secretkeeper_local.pp
```

### High CPU Usage

1. Check for too many monitored paths:
   ```bash
   sudo journalctl -u secretkeeper | grep "watch"
   ```

2. Add exclusions for noisy directories in config.

## Upgrading

### Package Upgrade

```bash
# Debian/Ubuntu
sudo dpkg -i secretkeeper_NEW_VERSION_amd64.deb

# RHEL/Fedora
sudo dnf upgrade ./secretkeeper-NEW_VERSION.x86_64.rpm
```

### Manual Upgrade

```bash
# Preserves configuration
sudo make upgrade-linux
```

## Uninstallation

### Package Removal

```bash
# Debian/Ubuntu (keeps config)
sudo apt remove secretkeeper

# Debian/Ubuntu (removes everything)
sudo apt purge secretkeeper

# RHEL/Fedora
sudo dnf remove secretkeeper
```

### Manual Removal

```bash
sudo make uninstall-linux
```

## Support

- GitHub Issues: https://github.com/secretkeeper/secretkeeper/issues
- Documentation: https://github.com/secretkeeper/secretkeeper/docs
