import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var appState: AppState
    @State private var selectedTab = SettingsTab.general

    enum SettingsTab: String, CaseIterable {
        case general = "General"
        case protection = "Protection"
        case notifications = "Notifications"
        case advanced = "Advanced"

        var icon: String {
            switch self {
            case .general: return "gear"
            case .protection: return "shield"
            case .notifications: return "bell"
            case .advanced: return "wrench.and.screwdriver"
            }
        }
    }

    var body: some View {
        TabView(selection: $selectedTab) {
            GeneralSettingsView()
                .tabItem {
                    Label(SettingsTab.general.rawValue, systemImage: SettingsTab.general.icon)
                }
                .tag(SettingsTab.general)

            ProtectionSettingsView()
                .tabItem {
                    Label(SettingsTab.protection.rawValue, systemImage: SettingsTab.protection.icon)
                }
                .tag(SettingsTab.protection)

            NotificationSettingsView()
                .tabItem {
                    Label(SettingsTab.notifications.rawValue, systemImage: SettingsTab.notifications.icon)
                }
                .tag(SettingsTab.notifications)

            AdvancedSettingsView()
                .tabItem {
                    Label(SettingsTab.advanced.rawValue, systemImage: SettingsTab.advanced.icon)
                }
                .tag(SettingsTab.advanced)
        }
        .frame(width: 550, height: 550)
    }
}

struct GeneralSettingsView: View {
    @EnvironmentObject var appState: AppState
    @State private var launchAtLogin = true
    @State private var showMenuBarIcon = true
    @State private var selectedMode = "block"

    var body: some View {
        Form {
            Section("Startup") {
                Toggle("Launch SecretKeeper at login", isOn: $launchAtLogin)
                Toggle("Show icon in menu bar", isOn: $showMenuBarIcon)
            }

            Section("Enforcement Mode") {
                Picker("Mode", selection: $selectedMode) {
                    Text("Block").tag("block")
                    Text("Monitor Only").tag("monitor")
                }
                .pickerStyle(.radioGroup)

                Text("Block mode prevents unauthorized access. Monitor mode only logs violations.")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Section("Agent Status") {
                if let status = appState.agentStatus {
                    LabeledContent("Status") {
                        HStack(spacing: 4) {
                            Circle()
                                .fill(Color.green)
                                .frame(width: 8, height: 8)
                            Text("Running")
                        }
                    }
                    LabeledContent("Mode") {
                        Text(status.mode.capitalized)
                            .font(.system(.body, design: .monospaced))
                    }
                    LabeledContent("Uptime") {
                        Text(formatUptime(status.uptimeSecs))
                            .font(.system(.body, design: .monospaced))
                    }
                    LabeledContent("Total Violations") {
                        Text("\(status.totalViolations)")
                            .font(.system(.body, design: .monospaced))
                    }
                } else {
                    LabeledContent("Status") {
                        HStack(spacing: 4) {
                            Circle()
                                .fill(Color.red)
                                .frame(width: 8, height: 8)
                            Text("Not Connected")
                        }
                    }
                }
            }
        }
        .formStyle(.grouped)
        .padding()
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
}

struct ProtectionSettingsView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        Form {
            Section("Protected File Categories") {
                if appState.categories.isEmpty {
                    Text("Loading categories...")
                        .foregroundColor(.secondary)
                } else {
                    ForEach(appState.categories) { category in
                        ProtectedCategoryRow(category: category)
                    }
                }
            }

            Section("Global Exclusions") {
                Text("Processes matching these patterns are always allowed to access protected files.")
                    .font(.caption)
                    .foregroundColor(.secondary)

                Text("Global exclusions are configured in the config file. Add entries under [global_exclusions] to allow specific processes.")
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .padding(.top, 4)

                Button("Edit Configuration File") {
                    NSWorkspace.shared.open(URL(fileURLWithPath: "/Library/Application Support/SecretKeeper/config.toml"))
                }
                .padding(.top, 4)
            }
        }
        .formStyle(.grouped)
        .padding()
    }
}

struct ProtectedCategoryRow: View {
    @EnvironmentObject var appState: AppState
    let category: ProtectedCategory

    private var isEnabled: Binding<Bool> {
        Binding(
            get: { category.enabled },
            set: { newValue in
                // Update local state
                appState.setCategoryEnabled(category.id, enabled: newValue)
                // Send IPC command
                if let appDelegate = AppDelegate.shared,
                   let ipcClient = appDelegate.ipcClient {
                    ipcClient.setCategoryEnabled(categoryId: category.id, enabled: newValue)
                }
                fputs("[Settings] Category '\(category.id)' \(newValue ? "enabled" : "disabled")\n", stderr)
            }
        )
    }

    private var icon: String {
        switch category.id {
        case "ssh_keys": return "key"
        case "aws_credentials": return "cloud"
        case "gcp_credentials": return "cloud"
        case "kubeconfig": return "server.rack"
        case "gpg_keys": return "lock.shield"
        case "npm_tokens": return "shippingbox"
        case "git_credentials": return "arrow.triangle.branch"
        default: return "doc.badge.gearshape"
        }
    }

    var body: some View {
        Toggle(isOn: isEnabled) {
            HStack {
                Image(systemName: icon)
                    .frame(width: 20)
                VStack(alignment: .leading) {
                    Text(category.id.replacingOccurrences(of: "_", with: " ").capitalized)
                    Text(category.patterns.joined(separator: ", "))
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                }
            }
        }
    }
}

struct NotificationSettingsView: View {
    @State private var showAlerts = true
    @State private var showBanners = true
    @State private var playSound = false
    @State private var alertStyle = AlertStyle.modal

    enum AlertStyle: String, CaseIterable {
        case modal = "Modal Window"
        case banner = "Banner Only"
        case silent = "Silent (Log Only)"
    }

    var body: some View {
        Form {
            Section("Violation Alerts") {
                Picker("Alert Style", selection: $alertStyle) {
                    ForEach(AlertStyle.allCases, id: \.self) { style in
                        Text(style.rawValue).tag(style)
                    }
                }

                Toggle("Show system notifications", isOn: $showBanners)
                Toggle("Play sound on violation", isOn: $playSound)
            }

            Section("Alert Behavior") {
                Text("Modal windows require action before dismissing. Banners auto-dismiss after 5 seconds.")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .formStyle(.grouped)
        .padding()
    }
}

struct AdvancedSettingsView: View {
    @EnvironmentObject var appState: AppState
    @State private var socketPath = "/var/run/secretkeeper.sock"
    @State private var retentionDays = 30
    @State private var showConfirmClear = false

    var body: some View {
        Form {
            Section("IPC Configuration") {
                LabeledContent("Socket Path") {
                    Text(socketPath)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                }

                LabeledContent("Connection Status") {
                    HStack(spacing: 4) {
                        Circle()
                            .fill(appState.isConnected ? Color.green : Color.red)
                            .frame(width: 8, height: 8)
                        Text(appState.isConnected ? "Connected" : "Disconnected")
                    }
                }

                Button("Reconnect") {
                    // Trigger reconnection
                }
                .disabled(appState.isConnected)
            }

            Section("Data Retention") {
                Stepper("Keep violations for \(retentionDays) days", value: $retentionDays, in: 7...365)

                Button("Clear Violation History", role: .destructive) {
                    showConfirmClear = true
                }
                .alert("Clear History?", isPresented: $showConfirmClear) {
                    Button("Cancel", role: .cancel) {}
                    Button("Clear", role: .destructive) {
                        // Clear history via IPC
                    }
                } message: {
                    Text("This will permanently delete all violation history.")
                }
            }

            Section("Diagnostics") {
                Button("Export Diagnostic Report") {
                    exportDiagnostics()
                }

                Button("Open Log File") {
                    NSWorkspace.shared.open(URL(fileURLWithPath: "/var/log/secretkeeper.log"))
                }

                Button("View Configuration File") {
                    NSWorkspace.shared.open(URL(fileURLWithPath: "/Library/Application Support/SecretKeeper/config.toml"))
                }
            }
        }
        .formStyle(.grouped)
        .padding()
    }

    private func exportDiagnostics() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.json]
        panel.nameFieldStringValue = "secretkeeper-diagnostics.json"

        panel.begin { response in
            if response == .OK, let url = panel.url {
                // Export diagnostics to file
                let diagnostics: [String: Any] = [
                    "timestamp": ISO8601DateFormatter().string(from: Date()),
                    "connected": appState.isConnected,
                    "agent_status": appState.agentStatus.map { [
                        "mode": $0.mode,
                        "uptime": $0.uptimeSecs,
                        "violations": $0.totalViolations
                    ] as [String : Any] } ?? [:],
                    "exception_count": appState.exceptions.count,
                    "pending_violations": appState.pendingViolations.count
                ]

                if let data = try? JSONSerialization.data(withJSONObject: diagnostics, options: .prettyPrinted) {
                    try? data.write(to: url)
                }
            }
        }
    }
}
