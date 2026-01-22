import SecretKeeperLib
import SwiftUI
import UniformTypeIdentifiers

struct ViolationHistoryView: View {
    @EnvironmentObject var appState: AppState
    @State private var searchText = ""
    @State private var selectedEntryId: String?
    @State private var sortOrder = [KeyPathComparator(\HistoryEntry.violation.timestamp, order: .reverse)]

    var filteredHistory: [HistoryEntry] {
        if searchText.isEmpty {
            return appState.violationHistory
        }
        return appState.violationHistory.filter { entry in
            entry.violation.filePath.localizedCaseInsensitiveContains(searchText) ||
            entry.violation.processPath.localizedCaseInsensitiveContains(searchText) ||
            (entry.violation.teamId?.localizedCaseInsensitiveContains(searchText) ?? false)
        }
    }

    var selectedEntry: HistoryEntry? {
        guard let id = selectedEntryId else { return nil }
        return filteredHistory.first { $0.id == id }
    }

    var body: some View {
        NavigationSplitView {
            Table(filteredHistory, selection: $selectedEntryId, sortOrder: $sortOrder) {
                TableColumn("Time", value: \.violation.timestamp) { entry in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(formatTime(entry.violation.timestamp))
                            .font(.system(.body, design: .monospaced))
                        Text(formatDate(entry.violation.timestamp))
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                }
                .width(min: 80, ideal: 100)

                TableColumn("Process") { entry in
                    HStack(spacing: 6) {
                        Circle()
                            .fill(signingColor(for: entry.violation))
                            .frame(width: 8, height: 8)
                        Text(entry.violation.processName)
                            .fontWeight(.medium)
                        Text("(\(entry.violation.processPid))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .width(min: 140, ideal: 180)

                TableColumn("File") { entry in
                    Text(entry.violation.filePath)
                        .font(.system(.body, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                .width(min: 200)

                TableColumn("Response") { entry in
                    UserActionBadge(action: entry.userAction)
                }
                .width(min: 90, ideal: 100)

                TableColumn("Status", value: \.violation.action) { entry in
                    AgentActionBadge(action: entry.violation.action)
                }
                .width(min: 80, ideal: 90)

                TableColumn("") { entry in
                    if wouldBeAllowedByExceptions(exceptions: appState.exceptions, violation: entry.violation) {
                        Image(systemName: "checkmark.shield.fill")
                            .foregroundStyle(.green)
                            .help("Covered by existing exception")
                    }
                }
                .width(30)
            }
            .searchable(text: $searchText, prompt: "Search violations...")
            .navigationTitle("Violation History")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        refreshHistory()
                    } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                    .help("Refresh history")
                }

                ToolbarItem(placement: .primaryAction) {
                    Button {
                        exportHistory()
                    } label: {
                        Image(systemName: "square.and.arrow.up")
                    }
                    .help("Export history")
                }
            }
            .overlay {
                if appState.violationHistory.isEmpty {
                    ContentUnavailableView(
                        "No Violations",
                        systemImage: "checkmark.shield",
                        description: Text("No violations have been recorded yet.")
                    )
                }
            }
        } detail: {
            if let entry = selectedEntry {
                HistoryDetailView(entry: entry)
            } else {
                ContentUnavailableView(
                    "Select a Violation",
                    systemImage: "exclamationmark.triangle",
                    description: Text("Select a violation from the list to see details.")
                )
            }
        }
        .frame(minWidth: 900, minHeight: 500)
    }

    private func formatTime(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        return formatter.string(from: date)
    }

    private func formatDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "MMM d"
        return formatter.string(from: date)
    }

    private func signingColor(for violation: ViolationEvent) -> Color {
        switch violation.signingStatus {
        case .platform: return .blue
        case .signed: return .green
        case .adhoc: return .orange
        case .unsigned: return .red
        }
    }

    private func refreshHistory() {
        AppDelegate.shared?.ipcClient?.getViolations(limit: 100)
    }

    private func exportHistory() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.json]
        panel.nameFieldStringValue = "violations-\(Date().ISO8601Format()).json"

        panel.begin { response in
            if response == .OK, let url = panel.url {
                exportToJSON(url: url)
            }
        }
    }

    private func exportToJSON(url: URL) {
        struct ExportEntry: Codable {
            let timestamp: Date
            let processPath: String
            let processPid: UInt32
            let filePath: String
            let userAction: String
            let agentAction: String
            let teamId: String?
            let signingId: String?
        }

        let entries = appState.violationHistory.map { entry in
            ExportEntry(
                timestamp: entry.violation.timestamp,
                processPath: entry.violation.processPath,
                processPid: entry.violation.processPid,
                filePath: entry.violation.filePath,
                userAction: entry.userAction.label,
                agentAction: entry.violation.action,
                teamId: entry.violation.teamId,
                signingId: entry.violation.signingId
            )
        }

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]

        if let data = try? encoder.encode(entries) {
            try? data.write(to: url)
        }
    }
}

// MARK: - User Action Badge

struct UserActionBadge: View {
    let action: UserAction

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: action.icon)
                .font(.caption)
            Text(action.label)
                .font(.caption)
                .fontWeight(.medium)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(backgroundColor)
        .foregroundColor(foregroundColor)
        .cornerRadius(6)
    }

    private var backgroundColor: Color {
        switch action {
        case .resumed: return .green.opacity(0.15)
        case .killed: return .red.opacity(0.15)
        case .allowed: return .blue.opacity(0.15)
        case .pending: return .orange.opacity(0.15)
        case .dismissed: return .gray.opacity(0.15)
        }
    }

    private var foregroundColor: Color {
        switch action {
        case .resumed: return .green
        case .killed: return .red
        case .allowed: return .blue
        case .pending: return .orange
        case .dismissed: return .secondary
        }
    }
}

// MARK: - Agent Action Badge

struct AgentActionBadge: View {
    let action: String

    var body: some View {
        Text(action.capitalized)
            .font(.caption)
            .fontWeight(.medium)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(backgroundColor)
            .foregroundColor(foregroundColor)
            .cornerRadius(4)
    }

    private var backgroundColor: Color {
        switch action.lowercased() {
        case "blocked": return .red.opacity(0.2)
        case "logged": return .orange.opacity(0.2)
        case "suspended": return .yellow.opacity(0.2)
        default: return .gray.opacity(0.2)
        }
    }

    private var foregroundColor: Color {
        switch action.lowercased() {
        case "blocked": return .red
        case "logged": return .orange
        case "suspended": return .yellow
        default: return .gray
        }
    }
}

// MARK: - History Detail View

struct HistoryDetailView: View {
    @EnvironmentObject var appState: AppState
    let entry: HistoryEntry
    @State private var showAddException = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Header
                headerSection

                Divider()

                // File info
                DetailSection(title: "Protected File") {
                    DetailRow(label: "Path", value: entry.violation.filePath)
                    if let ruleId = entry.violation.ruleId {
                        DetailRow(label: "Rule", value: ruleId)
                    }
                }

                // Process info
                DetailSection(title: "Process Information") {
                    DetailRow(label: "Path", value: entry.violation.processPath)
                    DetailRow(label: "PID", value: "\(entry.violation.processPid)")
                    if let ppid = entry.violation.parentPid {
                        DetailRow(label: "Parent PID", value: "\(ppid)")
                    }
                    if let euid = entry.violation.processEuid {
                        DetailRow(label: "Effective UID", value: "\(euid)")
                    }
                    if let cmdline = entry.violation.processCmdline {
                        DetailRow(label: "Command", value: cmdline)
                    }
                }

                // Signing info
                if entry.violation.teamId != nil || entry.violation.signingId != nil {
                    DetailSection(title: "Code Signing") {
                        if let teamId = entry.violation.teamId {
                            DetailRow(label: "Team ID", value: teamId)
                        }
                        if let signingId = entry.violation.signingId {
                            DetailRow(label: "Signing ID", value: signingId)
                        }
                    }
                }

                // Exception coverage - always show status
                exceptionCoverageSection

                // Process tree
                DetailSection(title: "Process Tree") {
                    ProcessTreeView(entries: entry.violation.processTree)
                }

                // Action buttons if process is still actionable
                if entry.isProcessActionable {
                    Divider()
                    actionButtons
                }

                Spacer()
            }
            .padding()
        }
        .navigationTitle("Violation Details")
    }

    private var headerSection: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 8) {
                    Circle()
                        .fill(signingColor)
                        .frame(width: 12, height: 12)
                    Text(entry.violation.processName)
                        .font(.title2)
                        .fontWeight(.bold)
                }

                Text(entry.violation.timestamp.formatted(date: .abbreviated, time: .standard))
                    .foregroundColor(.secondary)

                if let actionTime = entry.actionTimestamp {
                    HStack(spacing: 4) {
                        Text("Action taken:")
                            .foregroundColor(.secondary)
                        Text(actionTime.formatted(date: .omitted, time: .standard))
                            .foregroundColor(.secondary)
                    }
                    .font(.caption)
                }
            }

            Spacer()

            VStack(alignment: .trailing, spacing: 8) {
                UserActionBadge(action: entry.userAction)
                SigningBadge(status: entry.violation.signingStatus)
            }
        }
    }

    private var signingColor: Color {
        switch entry.violation.signingStatus {
        case .platform: return .blue
        case .signed: return .green
        case .adhoc: return .orange
        case .unsigned: return .red
        }
    }

    private var actionButtons: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 4) {
                Image(systemName: "pause.circle.fill")
                    .foregroundColor(.red)
                Text("Process or parent is stopped and awaiting action")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }

            HStack(spacing: 12) {
                Button {
                    handleKill()
                } label: {
                    Label("Kill Process", systemImage: "xmark.circle.fill")
                }
                .buttonStyle(.bordered)
                .tint(.red)
                .help("Terminate the process")

                Button {
                    handleResume()
                } label: {
                    Label("Resume", systemImage: "play.circle.fill")
                }
                .buttonStyle(.bordered)
                .tint(.orange)
                .help("Allow the process to continue")

                Spacer()

                Button {
                    handleAllow()
                } label: {
                    Label("Allow Permanently", systemImage: "checkmark.circle.fill")
                }
                .buttonStyle(.borderedProminent)
                .help("Allow and create an exception")
            }
        }
        .padding()
        .background(Color(nsColor: .quaternarySystemFill))
        .cornerRadius(8)
    }

    private func handleKill() {
        // Note: AppDelegate.handleKillProcess already calls appState.recordAction
        AppDelegate.shared?.handleKillProcess(eventId: entry.id)
    }

    private func handleResume() {
        // Note: AppDelegate.handleAllowOnce already calls appState.recordAction
        AppDelegate.shared?.handleAllowOnce(eventId: entry.id)
    }

    private func handleAllow() {
        // Note: AppDelegate.handleAllowPermanently already calls appState.recordAction
        AppDelegate.shared?.handleAllowPermanently(eventId: entry.id)
    }

    @ViewBuilder
    private var exceptionCoverageSection: some View {
        if let matchingException = findMatchingException(exceptions: appState.exceptions, violation: entry.violation) {
            // Covered by an exception
            DetailSection(title: "Exception Coverage") {
                HStack(spacing: 8) {
                    Image(systemName: "checkmark.shield.fill")
                        .foregroundStyle(.green)
                    Text("Covered by existing exception")
                        .fontWeight(.medium)
                        .foregroundStyle(.green)
                }
                DetailRow(label: "Pattern", value: matchingException.filePattern)
                if let processPath = matchingException.processPath {
                    DetailRow(label: "Process", value: processPath)
                }
                if let signerDesc = matchingException.signerDescription {
                    DetailRow(label: "Signer", value: signerDesc)
                }
                if matchingException.isPermanent {
                    DetailRow(label: "Duration", value: "Permanent")
                } else if let remaining = matchingException.timeRemaining {
                    DetailRow(label: "Expires", value: remaining)
                }
            }
        } else {
            // Not covered - show warning and option to add exception
            DetailSection(title: "Exception Coverage") {
                HStack(spacing: 8) {
                    Image(systemName: "exclamationmark.shield.fill")
                        .foregroundStyle(.orange)
                    Text("Not covered by any exception")
                        .fontWeight(.medium)
                    Spacer()
                    Button("Add Exception...") {
                        showAddException = true
                    }
                    .buttonStyle(.bordered)
                }
                Text("Future access to this file by this process will trigger another violation.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .sheet(isPresented: $showAddException) {
                AddExceptionSheet(violation: entry.violation)
            }
        }
    }
}

// MARK: - Supporting Views

struct DetailSection<Content: View>: View {
    let title: String
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.headline)
                .foregroundColor(.secondary)
            content
        }
    }
}

struct DetailRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack(alignment: .top) {
            Text(label)
                .foregroundColor(.secondary)
                .frame(width: 100, alignment: .trailing)
            Text(value)
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
        }
    }
}
