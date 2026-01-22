.PHONY: all build build-release test lint clean install uninstall upgrade verify check ui-macos ui-macos-debug ui-linux run-ui run-agent dev

CARGO := cargo
INSTALL_DIR := /usr/local/bin
CONFIG_DIR_MACOS := /Library/Application\ Support/SecretKeeper
CONFIG_DIR_LINUX := /etc/secretkeeper
CONFIG_DIR_FREEBSD := /usr/local/etc/secretkeeper

all: build

build:
	$(CARGO) build

build-agent:
	$(CARGO) build --release --package secretkeeper-agent

build-release:
	$(CARGO) build --release

test:
	$(CARGO) test
	@echo "Running Swift tests..."
	@cd ui-swift/SecretKeeper && DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
		/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/swift test

lint:
	$(CARGO) clippy -- -D warnings
	$(CARGO) fmt -- --check

fmt:
	$(CARGO) fmt

clean:
	$(CARGO) clean

# macOS installation
install-macos: build-release
	@echo "Installing SecretKeeper agent on macOS..."
	sudo mkdir -p /Library/PrivilegedHelperTools
	sudo mkdir -p $(CONFIG_DIR_MACOS)
	sudo mkdir -p /var/lib/secretkeeper
	sudo cp target/release/secretkeeper-agent /Library/PrivilegedHelperTools/
	sudo cp agent/config/default.toml $(CONFIG_DIR_MACOS)/config.toml
	sudo cp install/macos/com.codegroove.secretkeeper.agent.plist /Library/LaunchDaemons/
	sudo launchctl load /Library/LaunchDaemons/com.codegroove.secretkeeper.agent.plist
	@echo "SecretKeeper agent installed and started"

uninstall-macos:
	@echo "Uninstalling SecretKeeper agent from macOS..."
	-sudo launchctl unload /Library/LaunchDaemons/com.codegroove.secretkeeper.agent.plist
	-sudo rm -f /Library/LaunchDaemons/com.codegroove.secretkeeper.agent.plist
	-sudo rm -f /Library/PrivilegedHelperTools/secretkeeper-agent
	-sudo rm -rf $(CONFIG_DIR_MACOS)
	@echo "SecretKeeper agent uninstalled"

# Linux installation
install-linux: build-release
	@echo "Installing SecretKeeper agent on Linux..."
	sudo mkdir -p $(CONFIG_DIR_LINUX)
	sudo mkdir -p /var/lib/secretkeeper
	sudo cp target/release/secretkeeper-agent $(INSTALL_DIR)/
	sudo cp agent/config/default.toml $(CONFIG_DIR_LINUX)/config.toml
	sudo cp install/linux/secretkeeper.service /etc/systemd/system/
	sudo systemctl daemon-reload
	sudo systemctl enable secretkeeper
	sudo systemctl start secretkeeper
	@echo "SecretKeeper agent installed and started"

uninstall-linux:
	@echo "Uninstalling SecretKeeper agent from Linux..."
	-sudo systemctl stop secretkeeper
	-sudo systemctl disable secretkeeper
	-sudo rm -f /etc/systemd/system/secretkeeper.service
	-sudo systemctl daemon-reload
	-sudo rm -f $(INSTALL_DIR)/secretkeeper-agent
	-sudo rm -rf $(CONFIG_DIR_LINUX)
	@echo "SecretKeeper agent uninstalled"

# Upgrade targets - update binary without losing config
upgrade-macos: build-release
	@echo "Upgrading SecretKeeper agent on macOS..."
	@echo "Stopping agent..."
	-sudo launchctl unload /Library/LaunchDaemons/com.codegroove.secretkeeper.agent.plist 2>/dev/null || true
	-sudo pkill -f secretkeeper-agent 2>/dev/null || true
	@sleep 1
	@echo "Installing new binary..."
	sudo cp target/release/secretkeeper-agent /Library/PrivilegedHelperTools/
	@echo "Starting agent..."
	@if [ -f /Library/LaunchDaemons/com.codegroove.secretkeeper.agent.plist ]; then \
		sudo launchctl load /Library/LaunchDaemons/com.codegroove.secretkeeper.agent.plist; \
	else \
		sudo cp install/macos/com.codegroove.secretkeeper.agent.plist /Library/LaunchDaemons/; \
		sudo launchctl load /Library/LaunchDaemons/com.codegroove.secretkeeper.agent.plist; \
	fi
	@echo ""
	@echo "Upgrade complete. Check status with: sudo launchctl list | grep secretkeeper"
	@echo ""
	@echo "NOTE: If FDA was revoked, grant it to:"
	@echo "  /Library/PrivilegedHelperTools/secretkeeper-agent"
	@echo "Then run: make restart-macos"

restart-macos:
	@echo "Restarting SecretKeeper agent..."
	-sudo launchctl unload /Library/LaunchDaemons/com.codegroove.secretkeeper.agent.plist 2>/dev/null || true
	@sleep 1
	sudo launchctl load /Library/LaunchDaemons/com.codegroove.secretkeeper.agent.plist
	@echo "Agent restarted"

upgrade-linux: build-release
	@echo "Upgrading SecretKeeper agent on Linux..."
	sudo systemctl stop secretkeeper
	sudo cp target/release/secretkeeper-agent $(INSTALL_DIR)/
	sudo systemctl start secretkeeper
	@echo "Upgrade complete"

# FreeBSD installation
install-freebsd: build-release
	@echo "Installing SecretKeeper agent on FreeBSD..."
	sudo mkdir -p $(CONFIG_DIR_FREEBSD)
	sudo mkdir -p /var/db/secretkeeper
	sudo cp target/release/secretkeeper-agent $(INSTALL_DIR)/
	sudo cp agent/config/default.toml $(CONFIG_DIR_FREEBSD)/config.toml
	sudo cp install/freebsd/secretkeeper.rc /usr/local/etc/rc.d/secretkeeper
	sudo chmod +x /usr/local/etc/rc.d/secretkeeper
	sudo sysrc secretkeeper_enable="YES"
	sudo service secretkeeper start
	@echo "SecretKeeper agent installed and started"

uninstall-freebsd:
	@echo "Uninstalling SecretKeeper agent from FreeBSD..."
	-sudo service secretkeeper stop
	-sudo sysrc -x secretkeeper_enable
	-sudo rm -f /usr/local/etc/rc.d/secretkeeper
	-sudo rm -f $(INSTALL_DIR)/secretkeeper-agent
	-sudo rm -rf $(CONFIG_DIR_FREEBSD)
	@echo "SecretKeeper agent uninstalled"

# Platform detection
UNAME := $(shell uname -s)

install:
ifeq ($(UNAME),Darwin)
	$(MAKE) install-macos
else ifeq ($(UNAME),Linux)
	$(MAKE) install-linux
else ifeq ($(UNAME),FreeBSD)
	$(MAKE) install-freebsd
else
	@echo "Unsupported platform: $(UNAME)"
	@exit 1
endif

uninstall:
ifeq ($(UNAME),Darwin)
	$(MAKE) uninstall-macos
else ifeq ($(UNAME),Linux)
	$(MAKE) uninstall-linux
else ifeq ($(UNAME),FreeBSD)
	$(MAKE) uninstall-freebsd
else
	@echo "Unsupported platform: $(UNAME)"
	@exit 1
endif

upgrade:
ifeq ($(UNAME),Darwin)
	$(MAKE) upgrade-macos
else ifeq ($(UNAME),Linux)
	$(MAKE) upgrade-linux
else
	@echo "Upgrade not yet implemented for $(UNAME)"
	@exit 1
endif

restart:
ifeq ($(UNAME),Darwin)
	$(MAKE) restart-macos
else ifeq ($(UNAME),Linux)
	sudo systemctl restart secretkeeper
else
	@echo "Restart not yet implemented for $(UNAME)"
	@exit 1
endif

# Run pre-flight checks (same as 'secretkeeper-agent check')
check: build
	./target/debug/secretkeeper-agent check

# Verify installation is working
verify:
	@echo "Verifying SecretKeeper installation..."
	@echo ""
	@echo "1. Checking binary..."
ifeq ($(UNAME),Darwin)
	@test -f /Library/PrivilegedHelperTools/secretkeeper-agent && echo "   ✓ Binary installed" || echo "   ✗ Binary not found"
else
	@test -f $(INSTALL_DIR)/secretkeeper-agent && echo "   ✓ Binary installed" || echo "   ✗ Binary not found"
endif
	@echo ""
	@echo "2. Checking configuration..."
ifeq ($(UNAME),Darwin)
	@test -f "/Library/Application Support/SecretKeeper/config.toml" && echo "   ✓ Config file present" || echo "   ✗ Config file not found"
else ifeq ($(UNAME),Linux)
	@test -f /etc/secretkeeper/config.toml && echo "   ✓ Config file present" || echo "   ✗ Config file not found"
else ifeq ($(UNAME),FreeBSD)
	@test -f /usr/local/etc/secretkeeper/config.toml && echo "   ✓ Config file present" || echo "   ✗ Config file not found"
endif
	@echo ""
	@echo "3. Checking service status..."
ifeq ($(UNAME),Darwin)
	@launchctl list | grep -q secretkeeper && echo "   ✓ Service loaded" || echo "   ✗ Service not loaded"
else ifeq ($(UNAME),Linux)
	@systemctl is-active --quiet secretkeeper && echo "   ✓ Service active" || echo "   ✗ Service not active"
else ifeq ($(UNAME),FreeBSD)
	@service secretkeeper status >/dev/null 2>&1 && echo "   ✓ Service running" || echo "   ✗ Service not running"
endif
	@echo ""
	@echo "4. Checking socket..."
ifeq ($(UNAME),Darwin)
	@test -S /var/run/secretkeeper.sock && echo "   ✓ Socket available" || echo "   ✗ Socket not found"
else ifeq ($(UNAME),Linux)
	@test -S /var/run/secretkeeper.sock && echo "   ✓ Socket available" || echo "   ✗ Socket not found"
else ifeq ($(UNAME),FreeBSD)
	@test -S /var/run/secretkeeper.sock && echo "   ✓ Socket available" || echo "   ✗ Socket not found"
endif
	@echo ""
	@echo "5. Testing IPC connection..."
	@echo '{"action":"ping"}' | nc -U /var/run/secretkeeper.sock 2>/dev/null | grep -q "pong" && echo "   ✓ IPC responding" || echo "   ✗ IPC not responding"
	@echo ""
	@echo "Verification complete."

# Run all quality checks
qa: test lint
	@echo "All quality checks passed!"

# Build macOS Swift UI as app bundle
ui-macos: build-agent
	@echo "Building macOS Swift UI..."
	cd ui-swift/SecretKeeper && swift build -c release
	@echo "Creating app bundle..."
	@mkdir -p ui-swift/SecretKeeper/.build/SecretKeeper.app/Contents/MacOS
	@mkdir -p ui-swift/SecretKeeper/.build/SecretKeeper.app/Contents/Resources
	@cp ui-swift/SecretKeeper/.build/release/SecretKeeper ui-swift/SecretKeeper/.build/SecretKeeper.app/Contents/MacOS/
	@echo "Embedding agent binary..."
	@cp target/release/secretkeeper-agent ui-swift/SecretKeeper/.build/SecretKeeper.app/Contents/Resources/
	@echo "Embedding agent config..."
	@cp agent/config/default.toml ui-swift/SecretKeeper/.build/SecretKeeper.app/Contents/Resources/
	@cp agent/config/macos.toml ui-swift/SecretKeeper/.build/SecretKeeper.app/Contents/Resources/
	@echo "Embedding app icon..."
	@cp media/icons/AppIcon.icns ui-swift/SecretKeeper/.build/SecretKeeper.app/Contents/Resources/
	@echo "Embedding menubar icon..."
	@cp media/icons/MenuBarIconTemplate.png ui-swift/SecretKeeper/.build/SecretKeeper.app/Contents/Resources/
	@cp media/icons/MenuBarIconTemplate@2x.png ui-swift/SecretKeeper/.build/SecretKeeper.app/Contents/Resources/
	@echo '<?xml version="1.0" encoding="UTF-8"?>\n\
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n\
<plist version="1.0">\n\
<dict>\n\
	<key>CFBundleExecutable</key>\n\
	<string>SecretKeeper</string>\n\
	<key>CFBundleIconFile</key>\n\
	<string>AppIcon</string>\n\
	<key>CFBundleIdentifier</key>\n\
	<string>com.codegroove.secretkeeper.ui</string>\n\
	<key>CFBundleName</key>\n\
	<string>SecretKeeper</string>\n\
	<key>CFBundlePackageType</key>\n\
	<string>APPL</string>\n\
	<key>CFBundleShortVersionString</key>\n\
	<string>0.1.0</string>\n\
	<key>LSMinimumSystemVersion</key>\n\
	<string>14.0</string>\n\
	<key>LSUIElement</key>\n\
	<true/>\n\
	<key>NSHighResolutionCapable</key>\n\
	<true/>\n\
</dict>\n\
</plist>' > ui-swift/SecretKeeper/.build/SecretKeeper.app/Contents/Info.plist
	@echo "App bundle created at ui-swift/SecretKeeper/.build/SecretKeeper.app"

# Build macOS Swift UI as app bundle (debug)
ui-macos-debug: build-agent
	@echo "Building macOS Swift UI (debug)..."
	cd ui-swift/SecretKeeper && swift build
	@echo "Creating app bundle..."
	@mkdir -p ui-swift/SecretKeeper/.build/SecretKeeper.app/Contents/MacOS
	@mkdir -p ui-swift/SecretKeeper/.build/SecretKeeper.app/Contents/Resources
	@cp ui-swift/SecretKeeper/.build/debug/SecretKeeper ui-swift/SecretKeeper/.build/SecretKeeper.app/Contents/MacOS/
	@echo "Embedding agent binary..."
	@cp target/release/secretkeeper-agent ui-swift/SecretKeeper/.build/SecretKeeper.app/Contents/Resources/
	@echo "Embedding agent config..."
	@cp agent/config/default.toml ui-swift/SecretKeeper/.build/SecretKeeper.app/Contents/Resources/
	@cp agent/config/macos.toml ui-swift/SecretKeeper/.build/SecretKeeper.app/Contents/Resources/
	@echo "Embedding app icon..."
	@cp media/icons/AppIcon.icns ui-swift/SecretKeeper/.build/SecretKeeper.app/Contents/Resources/
	@echo "Embedding menubar icon..."
	@cp media/icons/MenuBarIconTemplate.png ui-swift/SecretKeeper/.build/SecretKeeper.app/Contents/Resources/
	@cp media/icons/MenuBarIconTemplate@2x.png ui-swift/SecretKeeper/.build/SecretKeeper.app/Contents/Resources/
	@echo '<?xml version="1.0" encoding="UTF-8"?>\n\
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n\
<plist version="1.0">\n\
<dict>\n\
	<key>CFBundleExecutable</key>\n\
	<string>SecretKeeper</string>\n\
	<key>CFBundleIconFile</key>\n\
	<string>AppIcon</string>\n\
	<key>CFBundleIdentifier</key>\n\
	<string>com.codegroove.secretkeeper.ui</string>\n\
	<key>CFBundleName</key>\n\
	<string>SecretKeeper</string>\n\
	<key>CFBundlePackageType</key>\n\
	<string>APPL</string>\n\
	<key>CFBundleShortVersionString</key>\n\
	<string>0.1.0</string>\n\
	<key>LSMinimumSystemVersion</key>\n\
	<string>14.0</string>\n\
	<key>LSUIElement</key>\n\
	<true/>\n\
	<key>NSHighResolutionCapable</key>\n\
	<true/>\n\
</dict>\n\
</plist>' > ui-swift/SecretKeeper/.build/SecretKeeper.app/Contents/Info.plist
	@echo "App bundle created at ui-swift/SecretKeeper/.build/SecretKeeper.app"

# Build Linux/FreeBSD Tauri UI
ui-linux:
	@echo "Building Linux/FreeBSD Tauri UI..."
	cd ui-tauri && $(CARGO) tauri build

# Build all UIs for the current platform
ui:
ifeq ($(UNAME),Darwin)
	$(MAKE) ui-macos
else
	$(MAKE) ui-linux
endif

# Full release build including UI
release: build-release ui
	@echo "Full release build complete!"

# Run agent in foreground for debugging (requires sudo for eslogger)
run-agent: build
	@echo "Starting SecretKeeper agent in foreground mode..."
	@echo "Press Ctrl+C to stop."
	@echo ""
	sudo RUST_LOG=debug ./target/debug/secretkeeper-agent --config agent/config/macos.toml

# Build and run the macOS UI (debug build as app bundle)
run-ui: ui-macos-debug
	@echo ""
	@echo "Starting SecretKeeper UI..."
	@echo "Note: The UI will prompt to install the agent if it's not running."
	@echo "For development, run 'make run-agent' in another terminal first."
	@echo ""
	./ui-swift/SecretKeeper/.build/SecretKeeper.app/Contents/MacOS/SecretKeeper

# Quick development workflow: build agent and UI
dev: build ui-macos-debug
	@echo ""
	@echo "Development build complete."
	@echo ""
	@echo "To run:"
	@echo "  Terminal 1: make run-agent"
	@echo "  Terminal 2: make run-ui"
