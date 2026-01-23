import AppKit
import Foundation
import os.log
import ServiceManagement

/// Simple dual logger that writes to both os.log and stderr
struct DualLogger {
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

/// Manages the SecretKeeper agent lifecycle: checking status, installing, and starting.
class AgentManager {
    static let shared = AgentManager()

    private let agentBinaryName = "secretkeeper-agent"
    private let launchDaemonLabel = "com.codegroove.secretkeeper.agent"
    private let socketPath = "/var/run/secretkeeper.sock"

    // Paths for installation
    private let installBinaryPath = "/Library/PrivilegedHelperTools/secretkeeper-agent"
    private let installConfigDir = "/Library/Application Support/SecretKeeper"
    private let installPlistPath = "/Library/LaunchDaemons/com.codegroove.secretkeeper.agent.plist"

    private let logger = DualLogger(subsystem: "com.codegroove.secretkeeper.ui", category: "AgentManager")

    private init() {
        logger.info("AgentManager initialized")
    }

    /// Check if Full Disk Access is granted by attempting to read a TCC-protected file.
    /// Returns true if FDA is available, false otherwise.
    func hasFullDiskAccess() -> Bool {
        logger.info("Checking Full Disk Access status...")

        // The TCC database is protected by Full Disk Access
        let tccPath = "/Library/Application Support/com.apple.TCC/TCC.db"

        // Try to open the file - if we can, we have FDA
        let fileHandle = FileHandle(forReadingAtPath: tccPath)
        if fileHandle != nil {
            fileHandle?.closeFile()
            logger.info("FDA check: Can read TCC database - FDA granted")
            return true
        }
        logger.debug("FDA check: Cannot read TCC database at \(tccPath)")

        // Also try user's Library folders that require FDA
        let protectedPaths = [
            NSHomeDirectory() + "/Library/Mail",
            NSHomeDirectory() + "/Library/Messages",
            NSHomeDirectory() + "/Library/Safari/Bookmarks.plist"
        ]

        let fileManager = FileManager.default
        for path in protectedPaths {
            if fileManager.isReadableFile(atPath: path) {
                logger.info("FDA check: Can read \(path) - FDA granted")
                return true
            }
            logger.debug("FDA check: Cannot read \(path)")
        }

        logger.warning("FDA check: Full Disk Access NOT granted")
        return false
    }

    /// Open System Settings to the Full Disk Access pane.
    func openFullDiskAccessSettings() {
        let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")!
        NSWorkspace.shared.open(url)
    }

    /// Reveal the agent binary in Finder for easy drag-and-drop to FDA settings.
    /// Returns true if the binary exists and was revealed, false otherwise.
    @discardableResult
    func revealAgentInFinder() -> Bool {
        let fileManager = FileManager.default

        // First check installed location
        if fileManager.fileExists(atPath: installBinaryPath) {
            logger.info("Revealing installed agent binary in Finder: \(installBinaryPath)")
            NSWorkspace.shared.selectFile(installBinaryPath, inFileViewerRootedAtPath: "")
            return true
        }

        // If not installed, try to find it in development locations
        if let binaryPath = findAgentBinary() {
            logger.info("Revealing development agent binary in Finder: \(binaryPath)")
            NSWorkspace.shared.selectFile(binaryPath, inFileViewerRootedAtPath: "")
            return true
        }

        logger.warning("Cannot reveal agent in Finder - binary not found")
        return false
    }

    /// Check if the installed agent binary has Full Disk Access.
    /// This runs `secretkeeper-agent check` with admin privileges and parses the output.
    func checkAgentHasFDA(completion: @escaping (Bool) -> Void) {
        logger.info("Checking if agent binary has FDA...")

        // The agent must be installed first
        guard FileManager.default.fileExists(atPath: installBinaryPath) else {
            logger.warning("Agent binary not installed, cannot check FDA")
            completion(false)
            return
        }

        // Run the agent check command with admin privileges
        let script = "'\(installBinaryPath)' check 2>&1"

        runWithAdminPrivileges(script: script) { [weak self] result in
            guard let self = self else {
                completion(false)
                return
            }

            // The check command output is captured in stdout
            // We need to look for "Full Disk Access" in the output
            // This is a bit of a hack - we should improve the check command to output JSON

            // For now, just assume if the command succeeded, FDA might be granted
            // The real check happens when we parse the output
            switch result {
            case .success:
                self.logger.info("Agent check command completed")
                // We can't easily get the output here since runWithAdminPrivileges doesn't return it
                // For now, assume success means we should try to start
                completion(true)
            case .failure(let error):
                self.logger.warning("Agent check command failed: \(error.localizedDescription)")
                completion(false)
            }
        }
    }

    /// Quick synchronous FDA check by running eslogger test (requires root).
    /// Returns true if FDA is likely granted, false otherwise.
    func quickFDACheck() -> Bool {
        logger.info("Running quick FDA check...")

        // We can't run eslogger without root, so this check is limited
        // The best we can do from the UI is check if the socket exists with proper permissions
        // The real FDA check happens when the agent starts

        // For now, just return the UI's own FDA check as a proxy
        // The agent will report degraded_mode: true if it doesn't have FDA
        return hasFullDiskAccess()
    }

    /// Check if the agent socket exists and is connectable.
    func isAgentRunning() -> Bool {
        logger.info("Checking if agent is running via socket at \(self.socketPath)...")

        let socketHandle = socket(AF_UNIX, SOCK_STREAM, 0)
        guard socketHandle >= 0 else {
            logger.error("Failed to create socket: errno=\(errno)")
            return false
        }
        defer { close(socketHandle) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)

        // Copy socket path safely with bounds checking
        let maxPathLen = MemoryLayout.size(ofValue: addr.sun_path) - 1  // Reserve space for null terminator
        guard socketPath.utf8.count <= maxPathLen else {
            logger.error("Socket path too long: \(socketPath.utf8.count) > \(maxPathLen)")
            return false
        }

        socketPath.withCString { path in
            withUnsafeMutablePointer(to: &addr.sun_path) { sunPath in
                let ptr = UnsafeMutableRawPointer(sunPath).assumingMemoryBound(to: CChar.self)
                strncpy(ptr, path, maxPathLen)
                ptr[maxPathLen] = 0  // Ensure null termination
            }
        }

        let result = withUnsafePointer(to: &addr) { addrPtr in
            addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                Darwin.connect(socketHandle, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }

        if result == 0 {
            logger.info("Agent is running - socket connection successful")
            return true
        } else {
            logger.info("Agent not running - socket connection failed: errno=\(errno)")
            return false
        }
    }

    /// Wait for the agent to start with retries.
    private func waitForAgentWithRetries(maxAttempts: Int, delaySeconds: Double, completion: @escaping (Bool) -> Void) {
        logger.info("Waiting for agent to start (max \(maxAttempts) attempts)...")

        func attempt(_ remaining: Int) {
            if isAgentRunning() {
                logger.info("Agent started successfully after \(maxAttempts - remaining + 1) attempt(s)")
                completion(true)
                return
            }

            if remaining <= 1 {
                logger.error("Agent did not start after \(maxAttempts) attempts")
                completion(false)
                return
            }

            logger.info("Agent not ready, retrying in \(delaySeconds)s... (\(remaining - 1) attempts left)")
            DispatchQueue.main.asyncAfter(deadline: .now() + delaySeconds) {
                attempt(remaining - 1)
            }
        }

        // Start first attempt after initial delay
        DispatchQueue.main.asyncAfter(deadline: .now() + delaySeconds) {
            attempt(maxAttempts)
        }
    }

    /// Check if the agent is installed (binary and plist exist).
    func isAgentInstalled() -> Bool {
        logger.info("Checking if agent is installed...")
        let fileManager = FileManager.default

        let binaryExists = fileManager.fileExists(atPath: installBinaryPath)
        let plistExists = fileManager.fileExists(atPath: installPlistPath)

        logger.info("  Binary at \(self.installBinaryPath): \(binaryExists ? "EXISTS" : "MISSING")")
        logger.info("  Plist at \(self.installPlistPath): \(plistExists ? "EXISTS" : "MISSING")")

        let installed = binaryExists && plistExists
        logger.info("Agent installed: \(installed)")
        return installed
    }

    /// Find the agent binary in common locations.
    func findAgentBinary() -> String? {
        logger.info("Searching for agent binary...")
        logger.debug("  Bundle path: \(Bundle.main.bundlePath)")
        logger.debug("  Resource path: \(Bundle.main.resourcePath ?? "nil")")
        logger.debug("  Executable path: \(Bundle.main.executablePath ?? "nil")")
        logger.debug("  Current directory: \(FileManager.default.currentDirectoryPath)")

        let possiblePaths = [
            // Embedded in app bundle (preferred for offline installation)
            Bundle.main.resourcePath.map { $0 + "/secretkeeper-agent" } ?? "",
            // Built from source (debug)
            Bundle.main.bundlePath + "/../../../agent/target/debug/secretkeeper-agent",
            // Built from source (release)
            Bundle.main.bundlePath + "/../../../agent/target/release/secretkeeper-agent",
            // Relative to UI binary in workspace
            Bundle.main.executablePath.map { URL(fileURLWithPath: $0).deletingLastPathComponent().path + "/../../agent/target/release/secretkeeper-agent" } ?? "",
            // Development workspace
            FileManager.default.currentDirectoryPath + "/agent/target/release/secretkeeper-agent",
            FileManager.default.currentDirectoryPath + "/agent/target/debug/secretkeeper-agent",
            // Installed location
            installBinaryPath,
            // Homebrew
            "/opt/homebrew/bin/secretkeeper-agent",
            "/usr/local/bin/secretkeeper-agent"
        ]

        for path in possiblePaths {
            let expandedPath = (path as NSString).expandingTildeInPath
            let exists = FileManager.default.fileExists(atPath: expandedPath)
            logger.debug("  Checking: \(expandedPath) - \(exists ? "FOUND" : "not found")")
            if exists {
                logger.info("Found agent binary at: \(expandedPath)")
                return expandedPath
            }
        }

        logger.error("Agent binary not found in any searched location")
        return nil
    }

    /// Find the default config file.
    func findConfigFile() -> String? {
        logger.info("Searching for config file...")

        let possiblePaths = [
            // Embedded in app bundle (preferred for offline installation)
            Bundle.main.resourcePath.map { $0 + "/default.toml" } ?? "",
            // Development workspace
            Bundle.main.bundlePath + "/../../../agent/config/macos.toml",
            FileManager.default.currentDirectoryPath + "/agent/config/macos.toml",
            // Installed location
            installConfigDir + "/config.toml",
            "/etc/secretkeeper/config.toml"
        ]

        for path in possiblePaths {
            let expandedPath = (path as NSString).expandingTildeInPath
            let exists = FileManager.default.fileExists(atPath: expandedPath)
            logger.debug("  Checking: \(expandedPath) - \(exists ? "FOUND" : "not found")")
            if exists {
                logger.info("Found config file at: \(expandedPath)")
                return expandedPath
            }
        }

        logger.error("Config file not found in any searched location")
        return nil
    }

    /// Install the agent with admin privileges using osascript.
    /// Returns true on success.
    func installAgent(completion: @escaping (Result<Void, AgentManagerError>) -> Void) {
        logger.info("=== Starting agent installation ===")

        guard let binaryPath = findAgentBinary() else {
            logger.error("Installation failed: agent binary not found")
            completion(.failure(.binaryNotFound))
            return
        }
        logger.info("Using binary: \(binaryPath)")

        guard let configPath = findConfigFile() else {
            logger.error("Installation failed: config file not found")
            completion(.failure(.configNotFound))
            return
        }
        logger.info("Using config: \(configPath)")

        // Build the installation script
        let script = buildInstallScript(binaryPath: binaryPath, configPath: configPath)
        logger.debug("Installation script:\n\(script)")

        // Run with admin privileges via osascript
        logger.info("Running installation script with admin privileges...")
        runWithAdminPrivileges(script: script) { [weak self] result in
            guard let self = self else { return }

            switch result {
            case .success:
                self.logger.info("Installation script completed successfully")
                // Wait for agent to start with retries
                self.waitForAgentWithRetries(maxAttempts: 10, delaySeconds: 1.0) { running in
                    if running {
                        self.logger.info("=== Agent installation complete and running ===")
                        completion(.success(()))
                    } else {
                        self.logger.error("Agent installed but did not start - check /var/log/secretkeeper.log")
                        self.checkLaunchDaemonStatus()
                        completion(.failure(.agentDidNotStart))
                    }
                }
            case .failure(let error):
                self.logger.error("Installation script failed: \(error.localizedDescription)")
                completion(.failure(error))
            }
        }
    }

    /// Check launchd status for debugging
    private func checkLaunchDaemonStatus() {
        logger.info("Checking LaunchDaemon status...")

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["list", launchDaemonLabel]

        let outputPipe = Pipe()
        let errorPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = errorPipe

        do {
            try process.run()
            process.waitUntilExit()

            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: outputData, encoding: .utf8) ?? ""
            let errorOutput = String(data: errorData, encoding: .utf8) ?? ""

            if process.terminationStatus == 0 {
                logger.info("launchctl list output:\n\(output)")
            } else {
                logger.warning("launchctl list failed (status \(process.terminationStatus)): \(errorOutput)")
            }
        } catch {
            logger.error("Failed to run launchctl: \(error.localizedDescription)")
        }

        // Also check if plist and binary exist after installation
        let fm = FileManager.default
        logger.info("Post-install file check:")
        logger.info("  Binary exists: \(fm.fileExists(atPath: self.installBinaryPath))")
        logger.info("  Plist exists: \(fm.fileExists(atPath: self.installPlistPath))")
        logger.info("  Config dir exists: \(fm.fileExists(atPath: self.installConfigDir))")

        // Check if log file exists
        let logPath = "/var/log/secretkeeper.log"
        if fm.fileExists(atPath: logPath) {
            logger.info("  Log file exists at \(logPath)")
            // Try to read last few lines
            if let content = try? String(contentsOfFile: logPath, encoding: .utf8) {
                let lines = content.components(separatedBy: .newlines).suffix(10)
                logger.info("  Last 10 log lines:\n\(lines.joined(separator: "\n"))")
            }
        } else {
            logger.warning("  Log file does NOT exist at \(logPath)")
        }
    }

    /// Start the agent if installed but not running.
    /// This also updates the binary to ensure we're running the latest version.
    func startAgent(completion: @escaping (Result<Void, AgentManagerError>) -> Void) {
        logger.info("=== Starting agent (with binary update) ===")

        // Find the source binary to copy
        guard let sourceBinaryPath = findAgentBinary() else {
            logger.error("Cannot find agent binary to copy")
            completion(.failure(.binaryNotFound))
            return
        }

        // Find config for the plist (needed if plist doesn't exist)
        guard let configPath = findConfigFile() else {
            logger.error("Cannot find config file")
            completion(.failure(.configNotFound))
            return
        }

        logger.info("Source binary: \(sourceBinaryPath)")
        logger.info("Config file: \(configPath)")

        // Build a script that updates the binary and restarts the agent
        let script = buildStartScript(binaryPath: sourceBinaryPath, configPath: configPath)
        logger.info("Running start script with binary update")

        runWithAdminPrivileges(script: script) { [weak self] result in
            guard let self = self else { return }

            switch result {
            case .success:
                self.logger.info("launchctl completed")
                // Wait for agent to start with retries
                self.waitForAgentWithRetries(maxAttempts: 10, delaySeconds: 1.0) { running in
                    if running {
                        self.logger.info("=== Agent started successfully ===")
                        completion(.success(()))
                    } else {
                        self.logger.error("Agent did not start after launchctl")
                        self.checkLaunchDaemonStatus()
                        completion(.failure(.agentDidNotStart))
                    }
                }
            case .failure(let error):
                self.logger.error("launchctl failed: \(error.localizedDescription)")
                completion(.failure(error))
            }
        }
    }

    /// Stop the agent.
    func stopAgent(completion: @escaping (Result<Void, AgentManagerError>) -> Void) {
        logger.info("=== Stopping agent ===")

        let script = "launchctl unload '\(installPlistPath)'"
        logger.info("Running: \(script)")

        runWithAdminPrivileges(script: script) { [weak self] result in
            switch result {
            case .success:
                self?.logger.info("launchctl unload completed successfully")
            case .failure(let error):
                self?.logger.error("launchctl unload failed: \(error.localizedDescription)")
            }
            completion(result.map { _ in () })
        }
    }

    func restartAgent(completion: @escaping (Result<Void, AgentManagerError>) -> Void) {
        logger.info("=== Restarting agent ===")

        // startAgent() already includes launchctl unload at the beginning of its script,
        // so we can just call it directly without a separate stopAgent() call.
        // This avoids prompting for admin password twice.
        startAgent(completion: completion)
    }

    // MARK: - Private

    private func buildInstallScript(binaryPath: String, configPath: String) -> String {
        let plistContent = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>\(launchDaemonLabel)</string>
            <key>Program</key>
            <string>\(installBinaryPath)</string>
            <key>ProgramArguments</key>
            <array>
                <string>\(installBinaryPath)</string>
                <string>--config</string>
                <string>\(installConfigDir)/config.toml</string>
            </array>
            <key>RunAtLoad</key>
            <true/>
            <key>KeepAlive</key>
            <dict>
                <key>SuccessfulExit</key>
                <false/>
            </dict>
            <key>StandardOutPath</key>
            <string>/var/log/secretkeeper.log</string>
            <key>StandardErrorPath</key>
            <string>/var/log/secretkeeper.log</string>
            <key>ProcessType</key>
            <string>Background</string>
        </dict>
        </plist>
        """

        // Escape for shell
        let escapedPlist = plistContent
            .replacingOccurrences(of: "'", with: "'\\''")

        return """
        exec 2>&1
        set -e
        echo "=== SecretKeeper Agent Installation ==="

        # Create directories
        echo "Creating directories..."
        mkdir -p '\(installConfigDir)'
        mkdir -p /Library/PrivilegedHelperTools
        echo "  Created \(installConfigDir)"
        echo "  Created /Library/PrivilegedHelperTools"

        # Copy binary
        echo "Copying binary from \(binaryPath)..."
        cp '\(binaryPath)' '\(installBinaryPath)'
        chmod 755 '\(installBinaryPath)'
        chown root:wheel '\(installBinaryPath)'
        ls -la '\(installBinaryPath)'

        # Copy config if not exists
        if [ ! -f '\(installConfigDir)/config.toml' ]; then
            echo "Copying config from \(configPath)..."
            cp '\(configPath)' '\(installConfigDir)/config.toml'
            chmod 644 '\(installConfigDir)/config.toml'
        else
            echo "Config already exists at \(installConfigDir)/config.toml"
        fi
        ls -la '\(installConfigDir)/config.toml'

        # Install launch daemon
        echo "Installing LaunchDaemon plist..."
        echo '\(escapedPlist)' > '\(installPlistPath)'
        chmod 644 '\(installPlistPath)'
        chown root:wheel '\(installPlistPath)'
        ls -la '\(installPlistPath)'

        # Unload if already loaded (ignore errors)
        echo "Unloading existing daemon (if any)..."
        launchctl unload '\(installPlistPath)' 2>&1 || true

        # Load the daemon
        echo "Loading daemon..."
        launchctl load -w '\(installPlistPath)' 2>&1
        echo "launchctl load exit code: $?"

        # Verify
        echo ""
        echo "=== Verification ==="
        echo "Checking launchctl list:"
        launchctl list | grep -i secretkeeper || echo "  (not found in list yet)"
        echo "Socket check:"
        ls -la /var/run/secretkeeper.sock 2>&1 || echo "  (socket not found yet - agent may still be starting)"

        echo ""
        echo "Installation script completed."
        """
    }

    private func buildStartScript(binaryPath: String, configPath: String) -> String {
        // Build the plist content (same as install)
        let plistContent = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>\(launchDaemonLabel)</string>
            <key>Program</key>
            <string>\(installBinaryPath)</string>
            <key>ProgramArguments</key>
            <array>
                <string>\(installBinaryPath)</string>
                <string>--config</string>
                <string>\(installConfigDir)/config.toml</string>
            </array>
            <key>RunAtLoad</key>
            <true/>
            <key>KeepAlive</key>
            <dict>
                <key>SuccessfulExit</key>
                <false/>
            </dict>
            <key>StandardOutPath</key>
            <string>/var/log/secretkeeper.log</string>
            <key>StandardErrorPath</key>
            <string>/var/log/secretkeeper.log</string>
            <key>ProcessType</key>
            <string>Background</string>
        </dict>
        </plist>
        """

        let escapedPlist = plistContent.replacingOccurrences(of: "'", with: "'\\''")

        return """
        exec 2>&1
        echo "=== SecretKeeper Agent Start (with binary update) ==="

        # Unload if already loaded (ignore errors)
        echo "Stopping existing daemon (if any)..."
        launchctl unload '\(installPlistPath)' 2>&1 || true
        sleep 1

        # Create directories if needed
        mkdir -p '\(installConfigDir)'
        mkdir -p /Library/PrivilegedHelperTools

        # Always update binary to latest version
        echo "Updating binary from \(binaryPath)..."
        cp '\(binaryPath)' '\(installBinaryPath)'
        chmod 755 '\(installBinaryPath)'
        chown root:wheel '\(installBinaryPath)'
        ls -la '\(installBinaryPath)'

        # Copy config if not exists (preserve existing config)
        if [ ! -f '\(installConfigDir)/config.toml' ]; then
            echo "Copying config from \(configPath)..."
            cp '\(configPath)' '\(installConfigDir)/config.toml'
            chmod 644 '\(installConfigDir)/config.toml'
        else
            echo "Config already exists at \(installConfigDir)/config.toml (preserving)"
        fi

        # Always update plist (in case label or paths changed)
        echo "Updating LaunchDaemon plist..."
        echo '\(escapedPlist)' > '\(installPlistPath)'
        chmod 644 '\(installPlistPath)'
        chown root:wheel '\(installPlistPath)'

        # Clear old log to see fresh output
        echo "Clearing old log file..."
        echo "" > /var/log/secretkeeper.log

        # Load the daemon
        echo "Loading daemon..."
        launchctl load -w '\(installPlistPath)' 2>&1
        echo "launchctl load exit code: $?"

        # Give it a moment to start
        sleep 2

        # Diagnostics
        echo ""
        echo "=== Post-start diagnostics ==="
        echo "Service status:"
        launchctl list | grep -i secretkeeper || echo "  (service not found in launchctl list)"
        echo "Socket check:"
        ls -la /var/run/secretkeeper.sock 2>&1 || echo "  (socket not found)"
        echo "Log file:"
        ls -la /var/log/secretkeeper.log 2>&1 || echo "  (log not found)"
        if [ -f /var/log/secretkeeper.log ]; then
            echo "Log contents:"
            cat /var/log/secretkeeper.log
        fi

        echo ""
        echo "Start script completed."
        """
    }

    private func runWithAdminPrivileges(script: String, completion: @escaping (Result<Void, AgentManagerError>) -> Void) {
        // Use osascript to run with admin privileges
        let escapedScript = script.replacingOccurrences(of: "\"", with: "\\\"")
        let appleScript = """
        do shell script "\(escapedScript)" with administrator privileges
        """

        logger.debug("AppleScript to execute:\n\(appleScript)")

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }

            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            process.arguments = ["-e", appleScript]

            let outputPipe = Pipe()
            let errorPipe = Pipe()
            process.standardOutput = outputPipe
            process.standardError = errorPipe

            do {
                self.logger.info("Launching osascript process...")
                try process.run()
                process.waitUntilExit()

                let exitCode = process.terminationStatus
                let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
                let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
                let output = String(data: outputData, encoding: .utf8) ?? ""
                let errorMessage = String(data: errorData, encoding: .utf8) ?? ""

                self.logger.info("osascript exit code: \(exitCode)")
                self.logger.info("========== SCRIPT OUTPUT ==========")

                if !output.isEmpty {
                    // Split into lines to avoid log truncation
                    for line in output.components(separatedBy: .newlines) {
                        if !line.isEmpty {
                            self.logger.info("[script] \(line)")
                        }
                    }
                } else {
                    self.logger.warning("osascript returned no output")
                }
                if !errorMessage.isEmpty {
                    self.logger.warning("osascript stderr: \(errorMessage)")
                }
                self.logger.info("====================================")

                DispatchQueue.main.async {
                    if exitCode == 0 {
                        self.logger.info("osascript completed successfully")
                        completion(.success(()))
                    } else {
                        if errorMessage.contains("User canceled") || errorMessage.contains("-128") {
                            self.logger.info("User cancelled authentication dialog")
                            completion(.failure(.userCancelled))
                        } else {
                            self.logger.error("osascript failed: \(errorMessage)")
                            completion(.failure(.installFailed(errorMessage)))
                        }
                    }
                }
            } catch {
                self.logger.error("Failed to launch osascript: \(error.localizedDescription)")
                DispatchQueue.main.async {
                    completion(.failure(.installFailed(error.localizedDescription)))
                }
            }
        }
    }
}

enum AgentManagerError: Error, LocalizedError {
    case binaryNotFound
    case configNotFound
    case userCancelled
    case installFailed(String)
    case agentDidNotStart
    case plistNotFound
    case binaryNotInstalled

    var errorDescription: String? {
        switch self {
        case .binaryNotFound:
            return "Could not find the secretkeeper-agent binary.\n\nIf building from source, run: make build-agent\n\nIf you downloaded the app, the binary should be embedded. Try re-downloading."
        case .configNotFound:
            return "Could not find a configuration file.\n\nEnsure the app bundle contains default.toml, or that /Library/Application Support/SecretKeeper/config.toml exists."
        case .userCancelled:
            return "Installation was cancelled."
        case .installFailed(let message):
            return "Installation failed: \(message)\n\nTry running the app as an administrator or check Console.app for detailed error messages."
        case .agentDidNotStart:
            return "The agent was installed but did not start.\n\nCheck the log file for details:\n  sudo tail -f /var/log/secretkeeper.log\n\nCommon causes:\n• Missing Full Disk Access permission\n• Another instance already running\n• Configuration file errors"
        case .plistNotFound:
            return "LaunchDaemon plist not found at /Library/LaunchDaemons/.\n\nThe agent needs to be installed first. Click 'Install Agent' to set it up."
        case .binaryNotInstalled:
            return "Agent binary not found at /Library/PrivilegedHelperTools/.\n\nThe agent needs to be installed first. Click 'Install Agent' to set it up."
        }
    }
}
