import SwiftUI

extension Notification.Name {
    static let restartAgent = Notification.Name("restartAgent")
}

struct MenuBarView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Image(systemName: "lock.shield.fill")
                    .foregroundColor(.blue)
                Text("SecretKeeper")
                    .font(.headline)
                Spacer()
                ConnectionIndicator(isConnected: appState.isConnected)
            }
            .padding()
            .background(Color(NSColor.windowBackgroundColor))

            Divider()

            // Status
            VStack(alignment: .leading, spacing: 8) {
                if let status = appState.agentStatus {
                    StatusRow(label: "Mode", value: status.mode.capitalized)
                    StatusRow(label: "Uptime", value: formatUptime(status.uptimeSecs))
                    StatusRow(label: "Total Violations", value: "\(status.totalViolations)")

                    // Degraded mode warning
                    if status.degradedMode {
                        HStack(alignment: .top, spacing: 8) {
                            Image(systemName: "xmark.shield.fill")
                                .foregroundStyle(.red)
                                .font(.system(size: 14))
                            Text("Protection DISABLED. Grant Full Disk Access to enable file monitoring.")
                                .font(.caption)
                                .foregroundColor(.red)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        .padding(8)
                        .background(Color.red.opacity(0.1))
                        .cornerRadius(6)
                    }
                } else if appState.isConnected {
                    Text("Loading status...")
                        .foregroundColor(.secondary)
                } else {
                    Text("Agent not connected")
                        .foregroundColor(.red)
                }
            }
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)

            Divider()

            // Pending violations
            if !appState.pendingViolations.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Pending Violations")
                        .font(.headline)
                        .foregroundColor(.orange)

                    ForEach(appState.pendingViolations.prefix(3)) { violation in
                        PendingViolationRow(violation: violation)
                    }

                    if appState.pendingViolations.count > 3 {
                        Text("+ \(appState.pendingViolations.count - 3) more...")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
                .padding()

                Divider()
            }

            // Quick actions
            VStack(spacing: 2) {
                MenuButton(title: "Violation History", icon: "clock.arrow.circlepath") {
                    openWindow(id: "history")
                }

                MenuButton(title: "Exception Manager", icon: "checkmark.shield") {
                    openWindow(id: "exceptions")
                }

                MenuButton(title: "Settings", icon: "gear") {
                    openSettings()
                }

                Divider()
                    .padding(.vertical, 4)

                MenuButton(title: "Restart Agent", icon: "arrow.clockwise") {
                    NotificationCenter.default.post(name: .restartAgent, object: nil)
                }

                MenuButton(title: "Quit SecretKeeper", icon: "power") {
                    NSApplication.shared.terminate(nil)
                }
            }
            .padding(.vertical, 8)
        }
        .frame(width: 320)
    }

    private func formatUptime(_ seconds: Int) -> String {
        let hours = seconds / 3600
        let minutes = (seconds % 3600) / 60

        if hours > 0 {
            return "\(hours)h \(minutes)m"
        } else {
            return "\(minutes)m"
        }
    }

    private func openWindow(id: String) {
        // Close the popover first
        if let popover = (NSApp.delegate as? AppDelegate)?.popover {
            popover.performClose(nil)
        }

        // Try to find and activate existing window
        if let window = NSApp.windows.first(where: { $0.identifier?.rawValue == id }) {
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
        } else {
            // Open via environment
            if let appDelegate = NSApp.delegate as? AppDelegate {
                appDelegate.openWindow(id: id)
            }
        }
    }

    private func openSettings() {
        // Close the popover first
        if let popover = (NSApp.delegate as? AppDelegate)?.popover {
            popover.performClose(nil)
        }

        // Open settings window
        NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
        NSApp.activate(ignoringOtherApps: true)
    }
}

struct ConnectionIndicator: View {
    let isConnected: Bool

    var body: some View {
        HStack(spacing: 4) {
            Circle()
                .fill(isConnected ? Color.green : Color.red)
                .frame(width: 8, height: 8)
            Text(isConnected ? "Connected" : "Disconnected")
                .font(.caption)
                .foregroundColor(.secondary)
        }
    }
}

struct StatusRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack {
            Text(label)
                .foregroundColor(.secondary)
            Spacer()
            Text(value)
                .fontWeight(.medium)
                .monospacedDigit()
        }
        .font(.system(.body, design: .monospaced))
    }
}

struct PendingViolationRow: View {
    let violation: ViolationEvent

    var body: some View {
        HStack {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundColor(.orange)
            VStack(alignment: .leading) {
                Text(violation.processName)
                    .font(.system(.body, design: .monospaced))
                    .lineLimit(1)
                Text(violation.filePath)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
            }
        }
        .padding(.vertical, 2)
    }
}

struct MenuButton: View {
    let title: String
    let icon: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack {
                Image(systemName: icon)
                    .frame(width: 20)
                Text(title)
                Spacer()
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
        }
        .buttonStyle(.plain)
        .background(Color.clear)
        .contentShape(Rectangle())
    }
}
