import SecretKeeperLib
import ServiceManagement
import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var appState: AppState
    @State private var selectedTab = SettingsTab.general

    enum SettingsTab: String, CaseIterable {
        case general = "General"
        case protection = "Protection"
        case exceptions = "Exceptions"

        var icon: String {
            switch self {
            case .general: return "gear"
            case .protection: return "shield"
            case .exceptions: return "checkmark.shield"
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

            ExceptionsSettingsView()
                .tabItem {
                    Label(SettingsTab.exceptions.rawValue, systemImage: SettingsTab.exceptions.icon)
                }
                .tag(SettingsTab.exceptions)
        }
        .frame(width: 500, height: 500)
    }
}

struct GeneralSettingsView: View {
    @EnvironmentObject var appState: AppState
    @State private var launchAtLogin = SMAppService.mainApp.status == .enabled

    private var launchAtLoginBinding: Binding<Bool> {
        Binding(
            get: { SMAppService.mainApp.status == .enabled },
            set: { newValue in
                do {
                    if newValue {
                        try SMAppService.mainApp.register()
                    } else {
                        try SMAppService.mainApp.unregister()
                    }
                    launchAtLogin = newValue
                } catch {
                    fputs("[Settings] Failed to update login item: \(error)\n", stderr)
                }
            }
        )
    }

    var body: some View {
        Form {
            Section {
                Toggle("Launch at Login", isOn: launchAtLoginBinding)
            }

            Section("Agent") {
                LabeledContent("Status") {
                    if let status = appState.agentStatus {
                        HStack(spacing: 6) {
                            Circle()
                                .fill(status.degradedMode ? .orange : .green)
                                .frame(width: 8, height: 8)
                            Text(status.degradedMode ? "Limited" : "Protected")
                        }
                    } else {
                        HStack(spacing: 6) {
                            Circle()
                                .fill(.red)
                                .frame(width: 8, height: 8)
                            Text("Not Running")
                        }
                    }
                }

                if let status = appState.agentStatus {
                    LabeledContent("Mode") {
                        Text(status.mode.replacingOccurrences(of: "-", with: " ").capitalized)
                    }
                }
            }
        }
        .formStyle(.grouped)
        .padding()
    }
}

struct ProtectionSettingsView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        Form {
            Section {
                if appState.categories.isEmpty {
                    Text("Loading...")
                        .foregroundColor(.secondary)
                } else {
                    ForEach(appState.categories) { category in
                        ProtectedCategoryRow(category: category)
                    }
                }
            } header: {
                Text("Protected Files")
            } footer: {
                Text("Toggle categories to enable or disable protection for specific file types.")
                    .font(.caption)
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
            get: {
                // Read live value from appState, not captured category
                appState.categories.first { $0.id == category.id }?.enabled ?? category.enabled
            },
            set: { newValue in
                // Update local state
                appState.setCategoryEnabled(category.id, enabled: newValue)
                // Send IPC command
                AppDelegate.shared?.ipcClient?.setCategoryEnabled(categoryId: category.id, enabled: newValue)
            }
        )
    }

    /// Display name for category IDs with proper capitalization
    private var displayName: String {
        switch category.id {
        // SSH
        case "ssh_keys": return "SSH Keys"
        case "ssh_host_keys": return "SSH Host Keys"
        case "root_ssh_keys": return "Root SSH Keys"
        // Cloud providers
        case "aws_credentials": return "AWS Credentials"
        case "aws_session": return "AWS Session Cache"
        case "gcloud_credentials": return "Google Cloud Credentials"
        case "gcp_adc": return "Google Cloud Application Default Credentials"
        case "azure_credentials": return "Azure Credentials"
        case "digitalocean": return "DigitalOcean Credentials"
        case "linode": return "Linode CLI Credentials"
        case "oci": return "Oracle Cloud Credentials"
        // Containers & orchestration
        case "kube_config": return "Kubernetes Config"
        case "docker_config": return "Docker Config"
        // Security
        case "gpg_keys": return "GPG Private Keys"
        case "vault_token": return "HashiCorp Vault Token"
        case "ansible_vault": return "Ansible Vault Password"
        case "pass_store": return "Pass Password Store"
        // Package managers
        case "npm_token": return "npm Token"
        case "pypi_token": return "PyPI Token"
        case "pip_config": return "pip Config"
        case "gem_credentials": return "RubyGems Credentials"
        case "cargo_credentials": return "Cargo/crates.io Credentials"
        // Shell history
        case "bash_history": return "Bash History"
        case "zsh_history": return "Zsh History"
        case "fish_history": return "Fish History"
        // Git & deployment
        case "git_credentials": return "Git Credentials"
        case "vercel": return "Vercel Credentials"
        case "netlify": return "Netlify Credentials"
        case "cloudflare": return "Cloudflare Credentials"
        // Databases
        case "postgresql": return "PostgreSQL Credentials"
        case "mysql": return "MySQL Credentials"
        // Network
        case "netrc": return "Network Credentials (.netrc)"
        // Fallback: replace underscores and capitalize each word
        default:
            return category.id
                .replacingOccurrences(of: "_", with: " ")
                .split(separator: " ")
                .map { word in
                    let s = String(word)
                    // Keep common acronyms uppercase
                    let acronyms = ["ssh", "aws", "gcp", "gpg", "npm", "api", "cli", "url"]
                    if acronyms.contains(s.lowercased()) {
                        return s.uppercased()
                    }
                    return s.capitalized
                }
                .joined(separator: " ")
        }
    }

    private var icon: String {
        switch category.id {
        // SSH
        case "ssh_keys", "ssh_host_keys", "root_ssh_keys": return "key"
        // Cloud
        case "aws_credentials", "aws_session": return "cloud"
        case "gcloud_credentials", "gcp_adc": return "cloud"
        case "azure_credentials": return "cloud"
        case "digitalocean", "linode", "oci": return "cloud"
        // Containers
        case "kube_config": return "server.rack"
        case "docker_config": return "shippingbox"
        // Security
        case "gpg_keys": return "lock.shield"
        case "vault_token", "ansible_vault", "pass_store": return "lock.fill"
        // Package managers
        case "npm_token", "pypi_token", "pip_config", "gem_credentials", "cargo_credentials": return "shippingbox"
        // Shell history
        case "bash_history", "zsh_history", "fish_history": return "terminal"
        // Git & deployment
        case "git_credentials": return "arrow.triangle.branch"
        case "vercel", "netlify", "cloudflare": return "globe"
        // Databases
        case "postgresql", "mysql": return "cylinder"
        // Network
        case "netrc": return "network"
        default: return "doc.badge.gearshape"
        }
    }

    var body: some View {
        Toggle(isOn: isEnabled) {
            HStack {
                Image(systemName: icon)
                    .frame(width: 20)
                VStack(alignment: .leading) {
                    Text(displayName)
                    Text(category.patterns.joined(separator: ", "))
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                }
            }
        }
    }
}

struct ExceptionsSettingsView: View {
    @EnvironmentObject var appState: AppState
    @State private var selectedExceptionId: Int64?
    @State private var showAddException = false

    var body: some View {
        VStack(spacing: 0) {
            if appState.exceptions.isEmpty {
                VStack(spacing: 12) {
                    Image(systemName: "checkmark.shield")
                        .font(.system(size: 40))
                        .foregroundColor(.secondary)
                    Text("No Exceptions")
                        .font(.headline)
                    Text("Exceptions allow specific processes to access protected files.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(appState.exceptions, selection: $selectedExceptionId) { exception in
                    ExceptionSettingsRow(exception: exception)
                        .tag(exception.id)
                }
            }

            Divider()

            HStack {
                Button {
                    showAddException = true
                } label: {
                    Image(systemName: "plus")
                }

                Button {
                    if let id = selectedExceptionId {
                        removeException(id: id)
                    }
                } label: {
                    Image(systemName: "minus")
                }
                .disabled(selectedExceptionId == nil)

                Spacer()

                Button("Refresh") {
                    AppDelegate.shared?.ipcClient?.getExceptions()
                }
            }
            .padding(8)
        }
        .sheet(isPresented: $showAddException) {
            QuickAddExceptionSheet()
        }
    }

    private func removeException(id: Int64) {
        AppDelegate.shared?.ipcClient?.removeException(id: id)
        appState.exceptions.removeAll { $0.id == id }
        selectedExceptionId = nil
    }
}

struct ExceptionSettingsRow: View {
    let exception: Exception

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            // What's allowed
            Text(exception.filePattern)
                .font(.system(.body, design: .monospaced))
                .lineLimit(1)

            // Who can access
            HStack(spacing: 12) {
                if let process = exception.processPath {
                    Label(process.components(separatedBy: "/").last ?? process, systemImage: "terminal")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                }
                if let signer = exception.codeSigner {
                    Label(signer, systemImage: "signature")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                }
                if !exception.isPermanent {
                    Label(exception.timeRemaining ?? "Expires", systemImage: "clock")
                        .font(.caption)
                        .foregroundColor(exception.isExpired ? .red : .orange)
                }
            }
        }
        .padding(.vertical, 2)
    }
}

struct QuickAddExceptionSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var processPath = ""
    @State private var filePattern = ""
    @State private var isPermanent = true

    var isValid: Bool {
        !processPath.isEmpty && !filePattern.isEmpty
    }

    var body: some View {
        VStack(spacing: 16) {
            Text("Add Exception")
                .font(.headline)

            Form {
                TextField("Process Path", text: $processPath)
                    .font(.system(.body, design: .monospaced))
                TextField("File Pattern", text: $filePattern)
                    .font(.system(.body, design: .monospaced))
                Toggle("Permanent", isOn: $isPermanent)
            }
            .formStyle(.grouped)

            HStack {
                Button("Cancel") {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)

                Spacer()

                Button("Add") {
                    // Capture all values before dismiss
                    let path = processPath
                    let pattern = filePattern
                    let isGlob = filePattern.contains("*")
                    let expiresAt: Date? = isPermanent ? nil : Date().addingTimeInterval(24 * 3600)

                    // Dismiss first, then do work
                    dismiss()

                    DispatchQueue.main.async {
                        AppDelegate.shared?.ipcClient?.addException(
                            processPath: path,
                            codeSigner: nil,
                            filePattern: pattern,
                            isGlob: isGlob,
                            expiresAt: expiresAt,
                            comment: nil
                        )
                        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
                            AppDelegate.shared?.ipcClient?.getExceptions()
                        }
                    }
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(!isValid)
            }
        }
        .padding()
        .frame(width: 400)
    }

}
