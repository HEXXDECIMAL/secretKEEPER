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
    }
}

class AppDelegate: NSObject, NSApplicationDelegate {
    /// Shared instance for access from SwiftUI views (since NSApp.delegate is wrapped by SwiftUI)
    static var shared: AppDelegate!

    var statusItem: NSStatusItem?
    var popover = NSPopover()
    let appState = AppState()
    var ipcClient: IPCClient?
    let agentManager = AgentManager.shared
    private var cancellables = Set<AnyCancellable>()
    /// Retain alert windows to prevent premature deallocation.
    private var alertWindows: [NSWindow] = []
    /// Reconnection state for exponential backoff.
    /// Note: Reconnection only tries to connect to the socket - it never prompts for password.
    private var reconnectAttempt = 0
    private let maxReconnectAttempts = 3
    private let baseReconnectDelay: TimeInterval = 5.0
    override init() {
        super.init()
        AppDelegate.shared = self
    }

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

        // Use SF Symbol shield icon
        button.image = NSImage(systemSymbolName: "lock.shield.fill", accessibilityDescription: "SecretKeeper")
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

        // Defer state changes to let popover fully close.
        // Modifying @Published properties while the popover's SwiftUI views
        // are still in the hierarchy can cause use-after-free crashes.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) { [weak self] in
            guard let self = self else { return }

            // Disconnect current IPC client
            self.ipcClient?.disconnect()
            self.appState.isConnected = false
            self.appState.agentStatus = nil
            self.reconnectAttempt = 0  // Reset retry counter for manual restart

            // Restart the agent
            self.startAgent()
        }
    }

    func openWindow(id: String) {
        // Check if window already exists
        for window in NSApp.windows {
            if window.identifier?.rawValue == id {
                window.makeKeyAndOrderFront(nil)
                NSApp.activate(ignoringOtherApps: true)
                return
            }
        }

        // Window doesn't exist - create it manually
        appLogger.info("Creating window: \(id)")

        let window: NSWindow
        let contentView: AnyView

        switch id {
        case "history":
            contentView = AnyView(
                ViolationHistoryView()
                    .environmentObject(appState)
            )
            window = NSWindow(
                contentRect: NSRect(x: 0, y: 0, width: 900, height: 600),
                styleMask: [.titled, .closable, .resizable, .miniaturizable],
                backing: .buffered,
                defer: false
            )
            window.title = "Violation History"

        case "settings":
            contentView = AnyView(
                SettingsView()
                    .environmentObject(appState)
            )
            window = NSWindow(
                contentRect: NSRect(x: 0, y: 0, width: 500, height: 500),
                styleMask: [.titled, .closable, .resizable],
                backing: .buffered,
                defer: false
            )
            window.title = "Settings"

        default:
            appLogger.warning("Unknown window id: \(id)")
            return
        }

        window.identifier = NSUserInterfaceItemIdentifier(id)
        window.contentView = NSHostingView(rootView: contentView)
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)

        // Retain the window to prevent premature deallocation
        alertWindows.append(window)

        // Clean up when window closes
        NotificationCenter.default.addObserver(
            forName: NSWindow.willCloseNotification,
            object: window,
            queue: .main
        ) { [weak self] notification in
            guard let closedWindow = notification.object as? NSWindow else { return }
            self?.alertWindows.removeAll { $0 === closedWindow }
        }
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
            // Use SF Symbol shield icon
            button.image = NSImage(systemSymbolName: "lock.shield.fill", accessibilityDescription: "SecretKeeper")
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

        // Load exceptions
        ipcClient?.getExceptions()
    }

    @objc func togglePopover() {
        guard let button = statusItem?.button else { return }

        // If popover is shown, just close it
        if popover.isShown {
            popover.performClose(nil)
            return
        }

        // Log state for debugging
        appLogger.info("Menubar clicked: connected=\(appState.isConnected), agentRunning=\(agentManager.isAgentRunning())")

        // If not connected, try to reconnect (just socket connection, no password prompt)
        if !appState.isConnected {
            appLogger.info("Not connected - attempting to reconnect...")
            reconnectAttempt = 0  // Reset counter for manual click
            connectToAgent()
        }

        // Show the popover
        popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
    }

    func showViolationAlert(_ violation: ViolationEvent) {
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }

            // Update app state
            self.appState.pendingViolations.append(violation)
            self.appState.totalViolations += 1

            // Add to history
            self.appState.addToHistory(violation)

            // Icon will be updated by the state observer

            // Show notification
            self.sendNotification(for: violation)

            // Open violation alert window
            let alertWindow = NSWindow(
                contentRect: NSRect(x: 0, y: 0, width: 680, height: 680),
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

            // Retain the window to prevent premature deallocation
            self.alertWindows.append(alertWindow)

            // Clean up when window closes
            NotificationCenter.default.addObserver(
                forName: NSWindow.willCloseNotification,
                object: alertWindow,
                queue: .main
            ) { [weak self] notification in
                guard let window = notification.object as? NSWindow else { return }
                self?.alertWindows.removeAll { $0 === window }
            }
        }
    }

    /// Show violation alert for an existing violation (from history).
    /// Does NOT add to pending violations or history - just shows the detail window.
    func showExistingViolationAlert(_ violation: ViolationEvent) {
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }

            // Open violation alert window
            let alertWindow = NSWindow(
                contentRect: NSRect(x: 0, y: 0, width: 680, height: 680),
                styleMask: [.titled, .closable],
                backing: .buffered,
                defer: false
            )
            alertWindow.title = "SecretKeeper - Violation Details"
            alertWindow.contentView = NSHostingView(
                rootView: ViolationAlertView(violation: violation)
                    .environmentObject(self.appState)
            )
            alertWindow.center()
            alertWindow.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)

            // Retain the window to prevent premature deallocation
            self.alertWindows.append(alertWindow)

            // Clean up when window closes
            NotificationCenter.default.addObserver(
                forName: NSWindow.willCloseNotification,
                object: alertWindow,
                queue: .main
            ) { [weak self] notification in
                guard let window = notification.object as? NSWindow else { return }
                self?.alertWindows.removeAll { $0 === window }
            }
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

    // MARK: - Violation Action Handlers

    /// Kill the suspended process.
    func handleKillProcess(eventId: String) {
        appLogger.info("Killing process for event: \(eventId)")
        ipcClient?.killProcess(eventId: eventId)
        appState.recordAction(.killed, forViolationId: eventId)
    }

    /// Allow the process to continue (one-time).
    func handleAllowOnce(eventId: String) {
        appLogger.info("Allowing once for event: \(eventId)")
        ipcClient?.allowOnce(eventId: eventId)
        appState.recordAction(.resumed, forViolationId: eventId)
    }

    /// Allow the process permanently and create exception.
    func handleAllowPermanently(eventId: String) {
        appLogger.info("Allowing permanently for event: \(eventId)")
        ipcClient?.allowPermanently(eventId: eventId)
        appState.recordAction(.allowed, forViolationId: eventId)
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

    func ipcClient(_ client: IPCClient, didReceiveCategories categories: [ProtectedCategory]) {
        appLogger.debug("Received \(categories.count) protected categories")
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.appState.categories = categories
        }
    }

    func ipcClient(_ client: IPCClient, didReceiveViolationHistory violations: [ViolationEvent]) {
        appLogger.info("Received \(violations.count) historical violations")
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            // Add historical violations to history (they come newest first from the agent)
            for violation in violations {
                // Only add if not already in history (avoid duplicates on reconnect)
                if self.appState.violationHistory.first(where: { $0.id == violation.id }) == nil {
                    // Historical violations have unknown user action - mark as dismissed
                    let entry = HistoryEntry(violation: violation, userAction: .dismissed)
                    self.appState.violationHistory.append(entry)
                }
            }
        }
    }

    func ipcClient(_ client: IPCClient, didReceiveExceptions exceptions: [Exception]) {
        appLogger.info("Received \(exceptions.count) exceptions")
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.appState.exceptions = exceptions
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

        // Ensure state updates on main thread
        let updateState = { [weak self] in
            self?.appState.isConnected = false
            self?.appState.agentStatus = nil
            self?.reconnectAttempt = 0  // Reset retry counter for manual restart
        }
        if Thread.isMainThread {
            updateState()
        } else {
            DispatchQueue.main.async(execute: updateState)
        }

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
            self?.reconnectAttempt = 0  // Reset on successful connection
        }
        // Request agent info for auto-upgrade check
        client.getAgentInfo()
        // Request status to check if agent is in degraded mode
        client.getStatus()
        // Request protected categories
        client.getCategories()
        // Request violation history
        client.getViolations(limit: 100)
    }

    func ipcClient(_ client: IPCClient, didReceiveAgentInfo info: AgentInfo) {
        appLogger.info("Received agent info: version=\(info.version), mtime=\(info.binaryMtime)")
        checkAndPerformAutoUpgrade(agentInfo: info)
    }

    private func checkAndPerformAutoUpgrade(agentInfo: AgentInfo) {
        // Get the embedded binary mtime from our app bundle
        guard let embeddedBinaryPath = agentManager.findAgentBinary() else {
            appLogger.warning("No embedded binary found for upgrade check")
            return
        }

        // Get embedded binary mtime
        guard let embeddedAttrs = try? FileManager.default.attributesOfItem(atPath: embeddedBinaryPath),
              let embeddedDate = embeddedAttrs[.modificationDate] as? Date else {
            appLogger.warning("Could not get embedded binary mtime")
            return
        }

        let embeddedMtime = Int64(embeddedDate.timeIntervalSince1970)
        let agentMtime = agentInfo.binaryMtime
        let ageDifference = embeddedMtime - agentMtime

        appLogger.info("Auto-upgrade check: embedded=\(embeddedMtime), agent=\(agentMtime), diff=\(ageDifference)s")

        // If the embedded binary is more than 60 seconds newer than the running agent, upgrade
        if ageDifference > 60 {
            appLogger.info("Agent binary is \(ageDifference)s older than embedded - triggering auto-upgrade")
            performSilentUpgrade()
        } else {
            appLogger.info("Agent binary is up to date (diff=\(ageDifference)s)")
        }
    }

    private func performSilentUpgrade() {
        // Auto-upgrade is disabled to avoid password prompt loops.
        // Users can manually restart via the menu to upgrade.
        appLogger.info("Auto-upgrade available but skipped (manual restart required)")
    }

    func ipcClientDidDisconnect(_ client: IPCClient) {
        appLogger.warning("IPC client disconnected from agent")
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.appState.isConnected = false

            // Check if we should attempt reconnection
            if self.reconnectAttempt >= self.maxReconnectAttempts {
                appLogger.error("Max reconnection attempts (\(self.maxReconnectAttempts)) reached - giving up")
                return
            }

            // Calculate delay with exponential backoff (capped at 60 seconds)
            let delay = min(self.baseReconnectDelay * pow(1.5, Double(self.reconnectAttempt)), 60.0)
            self.reconnectAttempt += 1

            appLogger.info("Will attempt to reconnect in \(String(format: "%.1f", delay))s (attempt \(self.reconnectAttempt)/\(self.maxReconnectAttempts))...")
            DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
                guard let self = self else { return }
                // Only reconnect if still disconnected (user might have manually reconnected)
                guard !self.appState.isConnected else {
                    appLogger.info("Already connected - skipping reconnection attempt")
                    return
                }
                appLogger.info("Attempting to reconnect to agent...")
                client.connect()
            }
        }
    }
}
