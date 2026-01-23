Name:           secretkeeper
Version:        %{?version}%{!?version:0.1.0}
Release:        1%{?dist}
Summary:        Secret exfiltration prevention daemon

License:        MIT
URL:            https://github.com/secretkeeper/secretkeeper
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cargo >= 1.70
BuildRequires:  rust >= 1.70
BuildRequires:  openssl-devel
%{?systemd_requires}
BuildRequires:  systemd-rpm-macros

Requires:       systemd
Requires(pre):  shadow-utils

%description
SecretKeeper monitors and protects sensitive files like SSH keys,
API tokens, and cloud credentials from unauthorized access.

Features:
- Kernel-level file access monitoring using fanotify
- True pre-access blocking (deny unauthorized access before it happens)
- Protection for 40+ credential categories
- Rule-based whitelist system
- Process tree tracking for violation attribution

Requires CAP_SYS_ADMIN capability and Linux kernel 5.1+.

%prep
# Source is the current directory (in-tree build)

%build
cargo build --release --package secretkeeper-agent

%install
# Install binary
install -D -m 755 target/release/secretkeeper-agent \
    %{buildroot}%{_bindir}/secretkeeper-agent

# Install systemd service
install -D -m 644 install/linux/secretkeeper.service \
    %{buildroot}%{_unitdir}/secretkeeper.service

# Install config
install -D -m 644 agent/config/default.toml \
    %{buildroot}%{_sysconfdir}/secretkeeper/config.toml

# Create data directory
install -d -m 750 %{buildroot}%{_localstatedir}/lib/secretkeeper

%pre
# Create secretkeeper user/group
getent group secretkeeper >/dev/null || groupadd -r secretkeeper
getent passwd secretkeeper >/dev/null || \
    useradd -r -g secretkeeper -d %{_localstatedir}/lib/secretkeeper \
    -s /sbin/nologin -c "SecretKeeper service account" secretkeeper
exit 0

%post
%systemd_post secretkeeper.service
echo "SecretKeeper installed successfully."
echo "Start with: systemctl start secretkeeper"
echo "View logs: journalctl -u secretkeeper -f"

%preun
%systemd_preun secretkeeper.service

%postun
%systemd_postun_with_restart secretkeeper.service

# Clean up on complete removal
if [ $1 -eq 0 ]; then
    # Remove data directory
    rm -rf %{_localstatedir}/lib/secretkeeper
fi

%files
%license LICENSE
%doc README.md
%{_bindir}/secretkeeper-agent
%{_unitdir}/secretkeeper.service
%dir %{_sysconfdir}/secretkeeper
%config(noreplace) %{_sysconfdir}/secretkeeper/config.toml
%dir %attr(750, root, root) %{_localstatedir}/lib/secretkeeper

%changelog
* Thu Jan 23 2025 SecretKeeper Team <team@secretkeeper.dev> - 0.1.0-1
- Initial release
- Linux support via fanotify with pre-access blocking
- Protection for SSH keys, GPG keys, cloud credentials, and more
- systemd service integration with security hardening
