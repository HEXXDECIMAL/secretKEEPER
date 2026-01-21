import Combine
import os.log
import SwiftUI
import UserNotifications

/// Simple dual logger that writes to both os.log and stderr
private struct AppDualLogger {
    let logger: Logger
    let category: String

    init(subsystem: String, category: String) {
        self.logger = Logger(subsystem: subsystem, category: category)
        self.category = category
    }

    func debug(_ message: String) {
        logger.debug("\(message)")
        fputs("[\(category)] DEBUG: \(message)\n", stderr)
    }

    func info(_ message: String) {
        logger.info("\(message)")
        fputs("[\(category)] \(message)\n", stderr)
    }

    func warning(_ message: String) {
        logger.warning("\(message)")
        fputs("[\(category)] ⚠️  \(message)\n", stderr)
    }

    func error(_ message: String) {
        logger.error("\(message)")
        fputs("[\(category)] ❌ \(message)\n", stderr)
    }
}

private let appLogger = AppDualLogger(subsystem: "com.codegroove.secretkeeper.ui", category: "App")

@main
struct SecretKeeperApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        Window("Settings", id: "settings") {
            SettingsView()
                .environmentObject(appDelegate.appState)
        }
        .windowResizability(.contentSize)
        .defaultPosition(.center)

        Window("Violation History", id: "history") {
            ViolationHistoryView()
                .environmentObject(appDelegate.appState)
        }

        Window("Exception Manager", id: "exceptions") {
            ExceptionManagerView()
                .environmentObject(appDelegate.appState)
        }
    }
}

class AppDelegate: NSObject, NSApplicationDelegate {
    var statusItem: NSStatusItem?
    var popover = NSPopover()
    let appState = AppState()
    var ipcClient: IPCClient?
    let agentManager = AgentManager.shared
    private var cancellables = Set<AnyCancellable>()

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Run as accessory app (menu bar only, no dock icon, no auto-shown windows)
        NSApp.setActivationPolicy(.accessory)

        // Close any auto-opened windows (SwiftUI opens Settings by default)
        for window in NSApp.windows {
            window.close()
        }

        // Print to console for users running from terminal
        print("""
        ┌─────────────────────────────────────────────────────────────────────┐
        │                    SecretKeeper UI Starting                         │
        ├─────────────────────────────────────────────────────────────────────┤
        │ To view detailed logs, run in another terminal:                     │
        │   log stream --predicate 'subsystem == "com.codegroove.secretkeeper.ui"'       │
        │                                                                     │
        │ Or view agent logs:                                                 │
        │   sudo tail -f /var/log/secretkeeper.log                            │
        └─────────────────────────────────────────────────────────────────────┘
        """)

        appLogger.info("=== SecretKeeper UI launching ===")
        appLogger.info("Bundle path: \(Bundle.main.bundlePath)")
        appLogger.info("Resource path: \(Bundle.main.resourcePath ?? "nil")")

        // Request notification permissions
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { granted, error in
            if let error = error {
                appLogger.warning("Notification permission error: \(error.localizedDescription)")
            } else {
                appLogger.info("Notification permission granted: \(granted)")
            }
        }

        setupMenuBar()
        setupNotificationObservers()
        setupStateObservers()
        checkAndStartAgent()
    }

    private func setupStateObservers() {
        // Observe connection state changes
        appState.$isConnected
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in
                self?.updateMenuBarIcon()
            }
            .store(in: &cancellables)

        // Observe agent status changes
        appState.$agentStatus
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in
                self?.updateMenuBarIcon()
            }
            .store(in: &cancellables)

        // Observe pending violations
        appState.$pendingViolations
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in
                self?.updateMenuBarIcon()
            }
            .store(in: &cancellables)
    }

    private func updateMenuBarIcon() {
        guard let button = statusItem?.button else { return }

        let iconName: String
        let tint: NSColor?

        if !appState.isConnected {
            // Disconnected - show warning icon
            iconName = "exclamationmark.shield.fill"
            tint = .systemRed
        } else if let status = appState.agentStatus {
            // Check for pending violations first (takes priority for visual attention)
            if !appState.pendingViolations.isEmpty {
                iconName = "exclamationmark.shield.fill"
                tint = .systemOrange
            } else {
                switch status.mode {
                case "disabled":
                    // FDA missing - protection disabled
                    iconName = "xmark.shield.fill"
                    tint = .systemRed
                case "best-effort":
                    // Active and working
                    iconName = "checkmark.shield.fill"
                    tint = nil  // Use default accent color
                case "block":
                    // Full blocking mode
                    iconName = "lock.shield.fill"
                    tint = nil
                case "monitor":
                    // Monitor only
                    iconName = "eye.fill"
                    tint = .secondaryLabelColor
                default:
                    iconName = "shield.fill"
                    tint = nil
                }
            }
        } else {
            // Connected but no status yet
            iconName = "shield.fill"
            tint = nil
        }

        var image = NSImage(systemSymbolName: iconName, accessibilityDescription: "SecretKeeper")

        // Apply tint if specified
        if let tint = tint, let img = image {
            let config = NSImage.SymbolConfiguration(paletteColors: [tint])
            image = img.withSymbolConfiguration(config)
        }

        button.image = image
    }

    private func setupNotificationObservers() {
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(handleRestartAgent),
            name: .restartAgent,
            object: nil
        )
    }

    @objc private func handleRestartAgent() {
        appLogger.info("User requested agent restart from menu")
        popover.performClose(nil)

        // Disconnect current IPC client
        ipcClient?.disconnect()
        appState.isConnected = false
        appState.agentStatus = nil

        // Restart the agent
        startAgent()
    }

    func openWindow(id: String) {
        // Use SwiftUI's openWindow environment action via NSApp
        // This is a workaround since we can't easily access @Environment from AppDelegate
        for window in NSApp.windows {
            if window.identifier?.rawValue == id {
                window.makeKeyAndOrderFront(nil)
                NSApp.activate(ignoringOtherApps: true)
                return
            }
        }

        // Window doesn't exist yet - we need to trigger SwiftUI to create it
        // Unfortunately this requires a bit of a hack with URL schemes or manual window creation
        appLogger.info("Opening window: \(id)")
    }

    private func checkAndStartAgent() {
        appLogger.info("Checking agent status...")

        if agentManager.isAgentRunning() {
            appLogger.info("Agent is already running - connecting")
            appState.agentInstalled = true
            connectToAgent()
            return
        }

        // Agent not running - check if installed
        if agentManager.isAgentInstalled() {
            appLogger.info("Agent is installed but not running - prompting to start")
            appState.agentInstalled = true
            showAgentNotRunningAlert(installed: true)
        } else {
            appLogger.info("Agent is not installed - prompting to install")
            appState.agentInstalled = false
            showAgentNotRunningAlert(installed: false)
        }
    }

    private func showAgentNotRunningAlert(installed: Bool) {
        appLogger.info("Showing agent not running alert (installed: \(installed))")
        // Just show install/start dialog - we'll check FDA status after agent starts via IPC
        showInstallOrStartAlert(installed: installed)
    }

    private func showFullDiskAccessWarning(installed: Bool) {
        let alert = NSAlert()
        alert.alertStyle = .critical
        alert.messageText = "Full Disk Access Required"
        alert.informativeText = """
        SecretKeeper CANNOT protect your files without Full Disk Access.

        Without FDA, the agent will start but file monitoring will be completely disabled. Your secrets will NOT be protected.

        To grant Full Disk Access:
        1. Click "Open System Settings"
        2. Click the + button to add an application
        3. Press Cmd+Shift+G and enter:
           /Library/PrivilegedHelperTools/
        4. Select "secretkeeper-agent" and click Open
        5. Come back here and click "I've Granted Access"

        The path will be copied to your clipboard.
        """

        alert.addButton(withTitle: "Open System Settings")
        alert.addButton(withTitle: installed ? "Start Without Protection" : "Install Without Protection")
        alert.addButton(withTitle: "Cancel")

        let response = alert.runModal()

        switch response {
        case .alertFirstButtonReturn:
            // Open System Settings and copy path to clipboard for convenience
            let pasteboard = NSPasteboard.general
            pasteboard.clearContents()
            pasteboard.setString("/Library/PrivilegedHelperTools/secretkeeper-agent", forType: .string)
            appLogger.info("Copied agent path to clipboard")

            agentManager.openFullDiskAccessSettings()

            // Show confirmation dialog
            showFDAConfirmationDialog(installed: installed)

        case .alertSecondButtonReturn:
            // Continue anyway without FDA
            appLogger.warning("User chose to continue without FDA protection")
            if installed {
                startAgent()
            } else {
                installAgent()
            }
        default:
            appState.isConnected = false
        }
    }

    private func showFDAConfirmationDialog(installed: Bool) {
        let alert = NSAlert()
        alert.alertStyle = .informational
        alert.messageText = "Have you granted Full Disk Access?"
        alert.informativeText = """
        After adding secretkeeper-agent to Full Disk Access:

        Click "I've Granted Access" to verify and continue.

        If you haven't done it yet, the path is in your clipboard:
        /Library/PrivilegedHelperTools/secretkeeper-agent
        """

        alert.addButton(withTitle: "I've Granted Access")
        alert.addButton(withTitle: "Open System Settings Again")
        alert.addButton(withTitle: "Skip (No Protection)")

        let response = alert.runModal()

        switch response {
        case .alertFirstButtonReturn:
            // User says they granted FDA - verify by trying to start the agent
            // We'll check the status after it starts
            appLogger.info("User confirmed FDA granted - proceeding with install/start")
            if installed {
                startAgent()
            } else {
                installAgent()
            }

        case .alertSecondButtonReturn:
            // Open settings again
            agentManager.openFullDiskAccessSettings()
            // Show this dialog again
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in
                self?.showFDAConfirmationDialog(installed: installed)
            }

        default:
            // Skip - start without protection
            appLogger.warning("User skipped FDA - starting without protection")
            if installed {
                startAgent()
            } else {
                installAgent()
            }
        }
    }

    private func showInstallOrStartAlert(installed: Bool) {
        let alert = NSAlert()
        alert.alertStyle = .informational

        if installed {
            alert.messageText = "SecretKeeper Agent Not Running"
            alert.informativeText = "The agent is installed but not running. Would you like to start it?\n\nThis requires administrator privileges."
            alert.addButton(withTitle: "Start Agent")
        } else {
            alert.messageText = "Install SecretKeeper Agent"
            alert.informativeText = """
            SecretKeeper requires a background agent to protect your secrets.

            The installation will:
            • Install the agent to /Library/PrivilegedHelperTools
            • Create a LaunchDaemon to run at startup
            • Copy the default configuration

            Administrator privileges required.
            """
            alert.addButton(withTitle: "Install Agent")
        }
        alert.addButton(withTitle: "Cancel")

        let response = alert.runModal()

        if response == .alertFirstButtonReturn {
            if installed {
                startAgent()
            } else {
                installAgent()
            }
        } else {
            appState.isConnected = false
        }
    }

    private func installAgent() {
        appLogger.info("User initiated agent installation")

        agentManager.installAgent { [weak self] result in
            DispatchQueue.main.async {
                switch result {
                case .success:
                    appLogger.info("Agent installation succeeded")
                    self?.appState.agentInstalled = true
                    self?.connectToAgent()

                    let successAlert = NSAlert()
                    successAlert.alertStyle = .informational
                    successAlert.messageText = "Installation Complete"
                    successAlert.informativeText = "The SecretKeeper agent has been installed and is now running.\n\n• Agent installed and running\n• Automatic startup enabled\n• Monitoring active"
                    successAlert.addButton(withTitle: "OK")
                    successAlert.runModal()

                case .failure(let error):
                    if case .userCancelled = error {
                        appLogger.info("User cancelled installation")
                        self?.appState.isConnected = false
                    } else {
                        appLogger.error("Agent installation failed: \(error.localizedDescription)")
                        let errorAlert = NSAlert()
                        errorAlert.alertStyle = .critical
                        errorAlert.messageText = "Installation Failed"
                        errorAlert.informativeText = error.localizedDescription
                        errorAlert.runModal()
                    }
                }
            }
        }
    }

    private func startAgent() {
        appLogger.info("User initiated agent start")

        agentManager.startAgent { [weak self] result in
            DispatchQueue.main.async {
                switch result {
                case .success:
                    appLogger.info("Agent started successfully")
                    self?.connectToAgent()

                case .failure(let error):
                    if case .userCancelled = error {
                        appLogger.info("User cancelled agent start")
                        self?.appState.isConnected = false
                    } else {
                        appLogger.error("Failed to start agent: \(error.localizedDescription)")
                        let errorAlert = NSAlert()
                        errorAlert.alertStyle = .critical
                        errorAlert.messageText = "Failed to Start Agent"
                        errorAlert.informativeText = error.localizedDescription
                        errorAlert.runModal()
                    }
                }
            }
        }
    }

    private func setupMenuBar() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)

        if let button = statusItem?.button {
            button.image = NSImage(systemSymbolName: "lock.shield", accessibilityDescription: "SecretKeeper")
            button.action = #selector(togglePopover)
            button.target = self
        }

        popover.contentSize = NSSize(width: 360, height: 400)
        popover.behavior = .transient
        popover.contentViewController = NSHostingController(
            rootView: MenuBarView()
                .environmentObject(appState)
        )
    }

    private func connectToAgent() {
        appLogger.info("Connecting to agent via IPC socket...")
        ipcClient = IPCClient(socketPath: "/var/run/secretkeeper.sock")
        ipcClient?.delegate = self
        ipcClient?.connect()

        // Subscribe to events
        appLogger.info("Subscribing to agent events")
        ipcClient?.subscribe()
    }

    @objc func togglePopover() {
        guard let button = statusItem?.button else { return }

        // If popover is shown, just close it
        if popover.isShown {
            popover.performClose(nil)
            return
        }

        // Check various bad states
        let isDisconnected = !appState.isConnected
        let isDegraded = appState.agentStatus?.degradedMode == true
        let isDisabledMode = appState.agentStatus?.mode == "disabled"
        let agentRunning = agentManager.isAgentRunning()

        appLogger.info("Menubar clicked: connected=\(appState.isConnected), degraded=\(isDegraded), disabled=\(isDisabledMode), agentRunning=\(agentRunning)")

        if isDisconnected && !agentRunning {
            // Agent not running at all - try to start it in background, but still show popover
            appLogger.info("Agent not running - attempting restart in background")
            attemptAgentRestart()
        } else if isDegraded || isDisabledMode {
            // Agent running but FDA missing - try restart silently in background
            appLogger.info("Agent in degraded/disabled mode - attempting silent restart")
            restartAgent()
        }

        // Always show the popover so user can access menu (including Quit)
        popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
    }

    private func attemptAgentRestart() {
        appLogger.info("Attempting to restart agent...")

        // Disconnect current IPC client
        ipcClient?.disconnect()
        appState.isConnected = false
        appState.agentStatus = nil

        // Check if agent is installed
        if agentManager.isAgentInstalled() {
            startAgent()
        } else {
            // Show install dialog
            showInstallOrStartAlert(installed: false)
        }
    }

    func showViolationAlert(_ violation: ViolationEvent) {
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }

            // Update app state
            self.appState.pendingViolations.append(violation)
            self.appState.totalViolations += 1

            // Icon will be updated by the state observer

            // Show notification
            self.sendNotification(for: violation)

            // Open violation alert window
            let alertWindow = NSWindow(
                contentRect: NSRect(x: 0, y: 0, width: 600, height: 500),
                styleMask: [.titled, .closable],
                backing: .buffered,
                defer: false
            )
            alertWindow.title = "SecretKeeper - Access Blocked"
            alertWindow.contentView = NSHostingView(
                rootView: ViolationAlertView(violation: violation)
                    .environmentObject(self.appState)
            )
            alertWindow.center()
            alertWindow.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
        }
    }

    private func sendNotification(for violation: ViolationEvent) {
        let content = UNMutableNotificationContent()
        content.title = "SecretKeeper: Access Blocked"
        content.subtitle = violation.processPath.components(separatedBy: "/").last ?? "Unknown"
        content.body = "Attempted to access \(violation.filePath)"
        content.sound = .default

        let request = UNNotificationRequest(
            identifier: UUID().uuidString,
            content: content,
            trigger: nil
        )

        UNUserNotificationCenter.current().add(request)
    }
}

extension AppDelegate: IPCClientDelegate {
    func ipcClient(_ client: IPCClient, didReceiveViolation violation: ViolationEvent) {
        appLogger.info("Received violation event: \(violation.processPath) -> \(violation.filePath)")
        showViolationAlert(violation)
    }

    func ipcClient(_ client: IPCClient, didUpdateStatus status: AgentStatus) {
        appLogger.debug("Received status update: mode=\(status.mode), degraded=\(status.degradedMode)")
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }

            let wasNotDegraded = self.appState.agentStatus?.degradedMode != true
            self.appState.agentStatus = status

            // Show FDA warning if agent is in degraded mode and we haven't shown it yet
            if status.degradedMode && wasNotDegraded {
                self.showDegradedModeAlert()
            }
        }
    }

    private func showDegradedModeAlert() {
        appLogger.warning("Agent is running without FDA - showing prompt")

        // Copy path to clipboard
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString("/Library/PrivilegedHelperTools/secretkeeper-agent", forType: .string)

        let alert = NSAlert()
        alert.alertStyle = .critical
        alert.messageText = "Protection Disabled"
        alert.informativeText = """
        SecretKeeper cannot protect your files without Full Disk Access.

        To enable protection:
        1. Click "Open System Settings"
        2. Click + then press Cmd+Shift+G
        3. Paste the path (already copied) and select the agent
        4. Click "Restart Agent" to apply changes

        Path copied: /Library/PrivilegedHelperTools/secretkeeper-agent
        """

        alert.addButton(withTitle: "Open Settings")
        alert.addButton(withTitle: "Check Again")
        alert.addButton(withTitle: "Later")

        let response = alert.runModal()
        switch response {
        case .alertFirstButtonReturn:
            // Open System Settings
            agentManager.openFullDiskAccessSettings()
        case .alertSecondButtonReturn:
            // Check Again - restart agent to see if FDA is now granted
            appLogger.info("User requested 'Check Again' - restarting agent")
            restartAgent()
        default:
            break
        }
    }

    private func restartAgent() {
        appLogger.info("Restarting agent...")

        // Disconnect current IPC client
        ipcClient?.disconnect()
        appState.isConnected = false
        appState.agentStatus = nil

        // Stop and restart the agent
        agentManager.restartAgent { [weak self] result in
            DispatchQueue.main.async {
                switch result {
                case .success:
                    appLogger.info("Agent restarted successfully")
                    self?.connectToAgent()
                case .failure(let error):
                    appLogger.error("Failed to restart agent: \(error.localizedDescription)")
                    let errorAlert = NSAlert()
                    errorAlert.alertStyle = .critical
                    errorAlert.messageText = "Failed to Restart Agent"
                    errorAlert.informativeText = error.localizedDescription
                    errorAlert.runModal()
                }
            }
        }
    }

    func ipcClientDidConnect(_ client: IPCClient) {
        appLogger.info("IPC client connected to agent")
        DispatchQueue.main.async { [weak self] in
            self?.appState.isConnected = true
        }
        // Request status to check if agent is in degraded mode
        client.getStatus()
    }

    func ipcClientDidDisconnect(_ client: IPCClient) {
        appLogger.warning("IPC client disconnected from agent")
        DispatchQueue.main.async { [weak self] in
            self?.appState.isConnected = false
            // Attempt to reconnect after a delay
            appLogger.info("Will attempt to reconnect in 5 seconds...")
            DispatchQueue.main.asyncAfter(deadline: .now() + 5) {
                appLogger.info("Attempting to reconnect to agent...")
                client.connect()
            }
        }
    }
}
