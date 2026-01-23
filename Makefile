.PHONY: all build build-release test lint clean install uninstall upgrade verify check ui-macos ui-macos-debug ui-linux run-ui run-agent dev
.PHONY: version bump-patch bump-minor bump-major app-bundle app-bundle-signed app-bundle-prod install-app dmg dmg-prod notarize out
.PHONY: package-deb package-rpm package

CARGO := cargo

#==============================================================================
# VERSION MANAGEMENT
#==============================================================================
VERSION_FILE := $(shell cat VERSION 2>/dev/null)
GIT_VERSION := $(shell git describe --tags --always 2>/dev/null)
BUILD_VERSION := $(or $(VERSION_FILE),$(GIT_VERSION),dev)
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# Build variant: dev (eslogger) or prod (ESF)
BUILD_VARIANT ?= dev
SIGNING_IDENTITY ?= -
ESF_SIGNING_IDENTITY ?= -

# Output paths
OUT_DIR := out
BUNDLE_NAME := SecretKeeper
BUNDLE_ID := com.codegroove.secretkeeper
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
	@if [ -d "/Applications/Xcode.app" ]; then \
		cd ui-swift/SecretKeeper && DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
			/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/swift test; \
	else \
		echo "Skipping Swift tests (Xcode not installed - only command line tools available)"; \
		echo "To run Swift tests, install Xcode from the App Store"; \
	fi

lint:
	$(CARGO) clippy -- -D warnings
	$(CARGO) fmt -- --check
	@echo "Checking Swift code..."
	@cd ui-swift/SecretKeeper && swift build 2>&1 | grep -E "(error:|warning:)" | grep -v "immutable property will not be decoded" || true
	@if command -v swiftlint >/dev/null 2>&1; then \
		echo "Running SwiftLint..."; \
		cd ui-swift/SecretKeeper && swiftlint lint --strict Sources/ 2>/dev/null || true; \
	else \
		echo "SwiftLint not installed (optional - install with: brew install swiftlint)"; \
	fi

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

upgrade-freebsd: build-release
	@echo "Upgrading SecretKeeper agent on FreeBSD..."
	sudo service secretkeeper stop || true
	sudo cp target/release/secretkeeper-agent $(INSTALL_DIR)/
	sudo service secretkeeper start
	@echo "Upgrade complete"

upgrade:
ifeq ($(UNAME),Darwin)
	$(MAKE) upgrade-macos
else ifeq ($(UNAME),Linux)
	$(MAKE) upgrade-linux
else ifeq ($(UNAME),FreeBSD)
	$(MAKE) upgrade-freebsd
else
	@echo "Upgrade not yet implemented for $(UNAME)"
	@exit 1
endif

restart-freebsd:
	@echo "Restarting SecretKeeper agent on FreeBSD..."
	sudo service secretkeeper restart
	@echo "Agent restarted"

restart:
ifeq ($(UNAME),Darwin)
	$(MAKE) restart-macos
else ifeq ($(UNAME),Linux)
	sudo systemctl restart secretkeeper
else ifeq ($(UNAME),FreeBSD)
	$(MAKE) restart-freebsd
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
	<string>$(BUILD_VERSION)</string>\n\
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
	<string>$(BUILD_VERSION)</string>\n\
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

#==============================================================================
# VERSION MANAGEMENT
#==============================================================================
version:
	@echo "Version: $(BUILD_VERSION)"
	@echo "Commit:  $(GIT_COMMIT)"
	@echo "Date:    $(BUILD_DATE)"
	@echo "Variant: $(BUILD_VARIANT)"

bump-patch bump-minor bump-major:
	@./scripts/bump-version.sh $(@:bump-%=%)

#==============================================================================
# APP BUNDLE BUILD (production bundles in out/)
#==============================================================================
out:
	@mkdir -p $(OUT_DIR)

# Build Swift UI (release)
ui-swift-release:
	cd ui-swift/SecretKeeper && swift build -c release

# Create unsigned app bundle (uses build-agent to avoid broken Tauri UI)
app-bundle: out build-agent ui-swift-release
	@echo "Creating app bundle ($(BUILD_VARIANT))..."
	@rm -rf "$(OUT_DIR)/$(BUNDLE_NAME).app"
	@mkdir -p "$(OUT_DIR)/$(BUNDLE_NAME).app/Contents/MacOS"
	@mkdir -p "$(OUT_DIR)/$(BUNDLE_NAME).app/Contents/Resources/en.lproj"
	# Copy executables
	@cp ui-swift/SecretKeeper/.build/release/SecretKeeper \
		"$(OUT_DIR)/$(BUNDLE_NAME).app/Contents/MacOS/"
	@cp target/release/secretkeeper-agent \
		"$(OUT_DIR)/$(BUNDLE_NAME).app/Contents/Resources/"
	# Copy configs
	@cp agent/config/default.toml agent/config/macos.toml \
		"$(OUT_DIR)/$(BUNDLE_NAME).app/Contents/Resources/"
	# Copy icons
	@cp media/icons/AppIcon.icns \
		"$(OUT_DIR)/$(BUNDLE_NAME).app/Contents/Resources/"
	@cp media/icons/MenuBarIconTemplate.png \
		media/icons/MenuBarIconTemplate@2x.png \
		"$(OUT_DIR)/$(BUNDLE_NAME).app/Contents/Resources/"
	# Generate Info.plist
	@/usr/libexec/PlistBuddy -c "Clear dict" \
		"$(OUT_DIR)/$(BUNDLE_NAME).app/Contents/Info.plist" 2>/dev/null || true
	@/usr/libexec/PlistBuddy \
		-c "Add :CFBundleExecutable string SecretKeeper" \
		-c "Add :CFBundleIdentifier string $(BUNDLE_ID).ui" \
		-c "Add :CFBundleName string SecretKeeper" \
		-c "Add :CFBundleIconFile string AppIcon" \
		-c "Add :CFBundlePackageType string APPL" \
		-c "Add :CFBundleShortVersionString string $(BUILD_VERSION)" \
		-c "Add :CFBundleVersion string $(BUILD_VERSION)" \
		-c "Add :LSMinimumSystemVersion string 14.0" \
		-c "Add :LSUIElement bool true" \
		-c "Add :NSHighResolutionCapable bool true" \
		-c "Add :CFBundleDevelopmentRegion string en" \
		-c "Add :CFBundleGetInfoString string SecretKeeper $(BUILD_VERSION)" \
		"$(OUT_DIR)/$(BUNDLE_NAME).app/Contents/Info.plist"
	@echo "Bundle created: $(OUT_DIR)/$(BUNDLE_NAME).app"

# Sign bundle (development - eslogger, ad-hoc or Developer ID)
app-bundle-signed: app-bundle
	@echo "Signing app bundle (dev variant)..."
	@xattr -cr "$(OUT_DIR)/$(BUNDLE_NAME).app"
	# Sign agent (no ESF entitlements for dev)
	@codesign --force --sign "$(SIGNING_IDENTITY)" \
		--entitlements install/macos/SecretKeeperAgent.entitlements \
		--options runtime \
		"$(OUT_DIR)/$(BUNDLE_NAME).app/Contents/Resources/secretkeeper-agent"
	# Sign main app
	@codesign --force --deep --sign "$(SIGNING_IDENTITY)" \
		--entitlements install/macos/SecretKeeper.entitlements \
		--options runtime \
		"$(OUT_DIR)/$(BUNDLE_NAME).app"
	@echo "Signed (dev): $(OUT_DIR)/$(BUNDLE_NAME).app"
	@codesign -dv "$(OUT_DIR)/$(BUNDLE_NAME).app" 2>&1 | head -5

# Sign bundle (production - ESF entitlements, requires Developer ID)
app-bundle-prod: BUILD_VARIANT=prod
app-bundle-prod: app-bundle
	@echo "Signing app bundle (prod variant with ESF)..."
	@xattr -cr "$(OUT_DIR)/$(BUNDLE_NAME).app"
	# Sign agent WITH ESF entitlements
	@codesign --force --sign "$(ESF_SIGNING_IDENTITY)" \
		--entitlements install/macos/SecretKeeperAgent-ESF.entitlements \
		--options runtime \
		"$(OUT_DIR)/$(BUNDLE_NAME).app/Contents/Resources/secretkeeper-agent"
	# Sign main app
	@codesign --force --deep --sign "$(ESF_SIGNING_IDENTITY)" \
		--entitlements install/macos/SecretKeeper.entitlements \
		--options runtime \
		"$(OUT_DIR)/$(BUNDLE_NAME).app"
	@echo "Signed (prod/ESF): $(OUT_DIR)/$(BUNDLE_NAME).app"
	@codesign -dv "$(OUT_DIR)/$(BUNDLE_NAME).app" 2>&1 | head -5

# Install to /Applications
install-app: app-bundle-signed
	@echo "Installing to /Applications..."
	@rm -rf "/Applications/$(BUNDLE_NAME).app"
	@cp -R "$(OUT_DIR)/$(BUNDLE_NAME).app" "/Applications/"
	@echo "Installed: /Applications/$(BUNDLE_NAME).app"

#==============================================================================
# DISTRIBUTION
#==============================================================================

# Create DMG
dmg: app-bundle-signed
	@echo "Creating DMG..."
	@rm -f "$(OUT_DIR)/$(BUNDLE_NAME)-$(BUILD_VERSION).dmg"
	@hdiutil create -volname "$(BUNDLE_NAME)" \
		-srcfolder "$(OUT_DIR)/$(BUNDLE_NAME).app" \
		-ov -format UDZO \
		"$(OUT_DIR)/$(BUNDLE_NAME)-$(BUILD_VERSION).dmg"
	@echo "Created: $(OUT_DIR)/$(BUNDLE_NAME)-$(BUILD_VERSION).dmg"

# Create production DMG with ESF
dmg-prod: app-bundle-prod
	@echo "Creating production DMG..."
	@rm -f "$(OUT_DIR)/$(BUNDLE_NAME)-$(BUILD_VERSION)-prod.dmg"
	@hdiutil create -volname "$(BUNDLE_NAME)" \
		-srcfolder "$(OUT_DIR)/$(BUNDLE_NAME).app" \
		-ov -format UDZO \
		"$(OUT_DIR)/$(BUNDLE_NAME)-$(BUILD_VERSION)-prod.dmg"
	@echo "Created: $(OUT_DIR)/$(BUNDLE_NAME)-$(BUILD_VERSION)-prod.dmg"

# Notarize (requires Apple Developer account and app-specific password)
# Setup: xcrun notarytool store-credentials "SecretKeeper" --apple-id "..." --team-id "..."
notarize: dmg-prod
	@echo "Submitting for notarization..."
	@xcrun notarytool submit "$(OUT_DIR)/$(BUNDLE_NAME)-$(BUILD_VERSION)-prod.dmg" \
		--keychain-profile "SecretKeeper" \
		--wait
	@xcrun stapler staple "$(OUT_DIR)/$(BUNDLE_NAME)-$(BUILD_VERSION)-prod.dmg"
	@echo "Notarization complete"

#==============================================================================
# LINUX PACKAGING
#==============================================================================

# Build Debian package (.deb)
package-deb:
	@echo "Building Debian package..."
	./packaging/build-deb.sh

# Build RPM package (.rpm)
package-rpm:
	@echo "Building RPM package..."
	./packaging/build-rpm.sh

# Build packages for current platform
package:
ifeq ($(UNAME),Linux)
	@if [ -f /etc/debian_version ]; then \
		$(MAKE) package-deb; \
	elif [ -f /etc/redhat-release ]; then \
		$(MAKE) package-rpm; \
	else \
		echo "Unknown Linux distribution. Use package-deb or package-rpm directly."; \
	fi
else
	@echo "Packaging is only supported on Linux"
	@exit 1
endif
