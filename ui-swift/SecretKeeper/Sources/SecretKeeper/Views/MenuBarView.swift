import SecretKeeperLib
import SwiftUI

extension Notification.Name {
    static let restartAgent = Notification.Name("restartAgent")
}

struct MenuBarView: View {
    @EnvironmentObject var appState: AppState
    @State private var historyExpanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            // Header with status
            headerSection

            // Show warning for disabled mode (FDA missing)
            if appState.agentStatus?.mode == "disabled" {
                disabledWarning
            }

            // Status info
            if let status = appState.agentStatus {
                statusSection(status)
            } else if !appState.isConnected {
                disconnectedSection
            }

            // Pending violations
            if !appState.pendingViolations.isEmpty {
                violationsSection
            }

            Divider()

            // Menu items
            menuSection
        }
        .padding(12)
        .frame(width: 280)
        .onDisappear {
            // Reset expanded state when popover closes to avoid stale view state
            historyExpanded = false
        }
    }

    // MARK: - Sections

    private var headerSection: some View {
        HStack {
            Image(systemName: headerIcon)
                .font(.system(size: 24))
                .foregroundStyle(headerIconColor)

            VStack(alignment: .leading, spacing: 2) {
                Text("SecretKeeper")
                    .font(.headline)
                Text(statusText)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            Spacer()
        }
    }

    private var headerIcon: String {
        guard appState.isConnected, let status = appState.agentStatus else {
            return "xmark.shield.fill"
        }
        switch status.mode {
        case "block":
            return "lock.shield.fill"
        case "best-effort":
            return "checkmark.shield.fill"
        case "monitor":
            return "eye.fill"
        case "disabled":
            return "xmark.shield.fill"
        default:
            return "shield.fill"
        }
    }

    private var headerIconColor: Color {
        guard appState.isConnected, let status = appState.agentStatus else {
            return .red
        }
        switch status.mode {
        case "block":
            return .accentColor
        case "best-effort":
            return .green
        case "monitor":
            return .secondary
        case "disabled":
            return .red
        default:
            return .accentColor
        }
    }

    private var statusText: String {
        if !appState.isConnected {
            return "Disconnected"
        } else if let status = appState.agentStatus {
            return modeDisplayName(status.mode)
        } else {
            return "Connecting..."
        }
    }

    private func modeDisplayName(_ mode: String) -> String {
        switch mode {
        case "block":
            return "Block Mode"
        case "best-effort":
            return "Active"
        case "monitor":
            return "Monitor Only"
        case "disabled":
            return "Protection Disabled"
        default:
            return mode.capitalized
        }
    }

    private var disabledWarning: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top, spacing: 8) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Full Disk Access Required")
                        .font(.caption)
                        .fontWeight(.medium)
                    Text("Grant FDA to enable file protection")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            Button("Open Privacy Settings...") {
                openPrivacySettings()
            }
            .font(.caption)
            .buttonStyle(.borderedProminent)
            .controlSize(.small)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.red.opacity(0.1))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private func openPrivacySettings() {
        // Close popover first
        AppDelegate.shared?.popover.performClose(nil)

        // Wait for popover to close, then open settings
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
            if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") {
                NSWorkspace.shared.open(url)
            }
        }
    }

    private func statusSection(_ status: AgentStatus) -> some View {
        VStack(spacing: 8) {
            StatusInfoRow(icon: "clock", label: "Uptime", value: formatUptime(status.uptimeSecs))
            StatusInfoRow(icon: "exclamationmark.triangle", label: "Violations", value: "\(status.totalViolations)")
        }
        .padding(10)
        .frame(maxWidth: .infinity)
        .background(Color(nsColor: .quaternarySystemFill))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private var disconnectedSection: some View {
        HStack(spacing: 8) {
            Image(systemName: "bolt.slash.fill")
                .foregroundStyle(.red)
            Text("Agent not connected")
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .quaternarySystemFill))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private var violationsSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Recent Violations")
                .font(.subheadline)
                .fontWeight(.medium)
                .foregroundStyle(.secondary)

            ForEach(appState.pendingViolations.prefix(3)) { violation in
                ViolationRow(violation: violation)
            }

            if appState.pendingViolations.count > 3 {
                Text("+\(appState.pendingViolations.count - 3) more")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
        }
    }

    private var menuSection: some View {
        VStack(spacing: 2) {
            // Violation History submenu
            violationHistorySubmenu

            MenuItem(title: "Settings...", icon: "gear") {
                openWindow(id: "settings")
            }

            Divider()
                .padding(.vertical, 4)

            MenuItem(title: "Restart Agent", icon: "arrow.clockwise") {
                NotificationCenter.default.post(name: .restartAgent, object: nil)
            }
            MenuItem(title: "Quit", icon: "power") {
                NSApplication.shared.terminate(nil)
            }
        }
    }

    private var violationHistorySubmenu: some View {
        VStack(spacing: 0) {
            // Header row - toggles expansion
            Button {
                withAnimation(.easeInOut(duration: 0.2)) {
                    historyExpanded.toggle()
                }
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: "clock.arrow.circlepath")
                        .frame(width: 16)
                        .foregroundStyle(.secondary)
                    Text("Violation History")
                    Spacer()
                    Text("\(appState.violationHistory.count)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color(nsColor: .tertiarySystemFill))
                        .clipShape(Capsule())
                    Image(systemName: historyExpanded ? "chevron.down" : "chevron.right")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .font(.body)
                .padding(.horizontal, 8)
                .padding(.vertical, 5)
                .background(historyExpanded ? Color(nsColor: .quaternarySystemFill) : .clear)
                .clipShape(RoundedRectangle(cornerRadius: 4))
            }
            .buttonStyle(.plain)

            // Expanded content
            if historyExpanded {
                VStack(spacing: 0) {
                    if appState.violationHistory.isEmpty {
                        Text("No violations recorded")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .padding(.vertical, 8)
                            .padding(.leading, 32)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    } else {
                        // Use Array() to avoid ArraySlice issues with ForEach
                        ForEach(Array(appState.violationHistory.prefix(10))) { entry in
                            HistoryEntryRow(entry: entry)
                        }

                        if appState.violationHistory.count > 10 {
                            Button {
                                openWindow(id: "history")
                            } label: {
                                HStack {
                                    Spacer()
                                    Text("View all \(appState.violationHistory.count) violations...")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                    Spacer()
                                }
                                .padding(.vertical, 6)
                            }
                            .buttonStyle(.plain)
                        }
                    }
                }
                .padding(.leading, 8)
                // Removed transition animation - can cause crashes during rapid popover open/close
            }
        }
    }

    // MARK: - Helpers

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
        // Capture id before view changes
        let windowId = id

        // Close popover first
        AppDelegate.shared?.popover.performClose(nil)

        // Wait for popover to fully close before opening window
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
            if let window = NSApp.windows.first(where: { $0.identifier?.rawValue == windowId }) {
                window.makeKeyAndOrderFront(nil)
                NSApp.activate(ignoringOtherApps: true)
            } else {
                AppDelegate.shared?.openWindow(id: windowId)
            }
        }
    }

}

// MARK: - Supporting Views

struct StatusInfoRow: View {
    let icon: String
    let label: String
    let value: String

    var body: some View {
        HStack {
            Label(label, systemImage: icon)
                .foregroundStyle(.secondary)
            Spacer()
            Text(value)
                .monospacedDigit()
        }
        .font(.subheadline)
    }
}

struct ViolationRow: View {
    let violation: ViolationEvent
    @State private var isHovering = false

    var body: some View {
        Button {
            openViolationAlert()
        } label: {
            HStack(spacing: 8) {
                Image(systemName: "exclamationmark.circle.fill")
                    .foregroundStyle(.orange)
                    .font(.subheadline)

                VStack(alignment: .leading, spacing: 1) {
                    Text(violation.processName)
                        .font(.subheadline)
                        .lineLimit(1)
                    Text(violation.filePath)
                        .font(.caption)
                        .foregroundStyle(isHovering ? .white.opacity(0.7) : .secondary)
                        .lineLimit(1)
                }

                Spacer()

                Image(systemName: "chevron.right")
                    .font(.caption)
                    .foregroundStyle(isHovering ? .white.opacity(0.7) : .secondary)
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(isHovering ? Color(nsColor: .selectedContentBackgroundColor) : .clear)
            .foregroundStyle(isHovering ? .white : .primary)
            .clipShape(RoundedRectangle(cornerRadius: 4))
        }
        .buttonStyle(.plain)
        .onHover { hovering in
            isHovering = hovering
        }
    }

    private func openViolationAlert() {
        // Capture violation before view changes
        let violation = self.violation

        // Close popover first
        AppDelegate.shared?.popover.performClose(nil)

        // Wait for popover to fully close before opening window
        // This prevents use-after-free when views are deallocated
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
            AppDelegate.shared?.showExistingViolationAlert(violation)
        }
    }
}

struct HistoryEntryRow: View {
    let entry: HistoryEntry
    @State private var isHovering = false

    var body: some View {
        Button {
            openViolationDetail()
        } label: {
            HStack(spacing: 8) {
                // Action indicator
                Image(systemName: entry.userAction.icon)
                    .font(.caption)
                    .foregroundStyle(actionColor)
                    .frame(width: 14)

                // Process name and file
                VStack(alignment: .leading, spacing: 1) {
                    Text(entry.violation.processName)
                        .font(.caption)
                        .fontWeight(.medium)
                        .lineLimit(1)
                    Text(entry.violation.filePath)
                        .font(.caption2)
                        .foregroundStyle(isHovering ? .white.opacity(0.7) : .secondary)
                        .lineLimit(1)
                }

                Spacer()

                // Timestamp
                Text(formatTime(entry.violation.timestamp))
                    .font(.caption2)
                    .foregroundStyle(isHovering ? .white.opacity(0.7) : .secondary)
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(isHovering ? Color(nsColor: .selectedContentBackgroundColor) : .clear)
            .foregroundStyle(isHovering ? .white : .primary)
            .clipShape(RoundedRectangle(cornerRadius: 4))
        }
        .buttonStyle(.plain)
        .onHover { hovering in
            isHovering = hovering
        }
    }

    private var actionColor: Color {
        switch entry.userAction {
        case .resumed: return .green
        case .killed: return .red
        case .allowed: return .blue
        case .pending: return .orange
        case .dismissed: return .secondary
        }
    }

    private func formatTime(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm"
        return formatter.string(from: date)
    }

    private func openViolationDetail() {
        // Capture ALL data before any view changes - this is the critical step
        let violationCopy = entry.violation

        // Escape button context completely before doing anything else
        DispatchQueue.main.async {
            // Open the detail window FIRST, before closing popover
            // This way the new window is set up before we tear down the popover
            AppDelegate.shared?.showExistingViolationAlert(violationCopy)

            // Close popover AFTER window is open, with delay for safety
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) {
                AppDelegate.shared?.popover.performClose(nil)
            }
        }
    }
}

struct MenuItem: View {
    let title: String
    let icon: String
    let action: () -> Void

    @State private var isHovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                Image(systemName: icon)
                    .frame(width: 16)
                    .foregroundStyle(.secondary)
                Text(title)
                Spacer()
            }
            .font(.body)
            .padding(.horizontal, 8)
            .padding(.vertical, 5)
            .background(isHovering ? Color(nsColor: .selectedContentBackgroundColor) : .clear)
            .foregroundStyle(isHovering ? .white : .primary)
            .clipShape(RoundedRectangle(cornerRadius: 4))
        }
        .buttonStyle(.plain)
        .onHover { hovering in
            isHovering = hovering
        }
    }
}
