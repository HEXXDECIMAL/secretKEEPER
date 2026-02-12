import SecretKeeperLib
import SwiftUI
import UniformTypeIdentifiers

struct ViolationHistoryView: View {
    @EnvironmentObject var appState: AppState
    @State private var searchText = ""
    @State private var selectedEntryId: String?
    @State private var sortOrder = [KeyPathComparator(\HistoryEntry.violation.timestamp, order: .reverse)]

    // Outcome filters
    @State private var showResumed = true
    @State private var showKilled = true
    @State private var showAllowed = true
    @State private var showPending = true
    @State private var showDismissed = true
    @State private var showLogged = true

    var filteredHistory: [HistoryEntry] {
        // Create a stable copy to avoid issues during view updates
        let allEntries = Array(appState.violationHistory)

        // Apply outcome filters
        let outcomeFiltered = allEntries.filter { entry in
            switch entry.userAction {
            case .resumed: return showResumed
            case .killed: return showKilled
            case .allowed: return showAllowed
            case .pending: return showPending
            case .dismissed: return showDismissed
            case .logged: return showLogged
            }
        }

        // Apply search filter
        let searchFiltered: [HistoryEntry]
        if searchText.isEmpty {
            searchFiltered = outcomeFiltered
        } else {
            let search = searchText.lowercased()
            searchFiltered = outcomeFiltered.filter { entry in
                entry.violation.filePath.localizedCaseInsensitiveContains(search) ||
                entry.violation.processPath.localizedCaseInsensitiveContains(search) ||
                entry.violation.processName.localizedCaseInsensitiveContains(search) ||
                (entry.violation.ruleId?.localizedCaseInsensitiveContains(search) ?? false) ||
                (entry.violation.teamId?.localizedCaseInsensitiveContains(search) ?? false)
            }
        }

        // Apply sorting
        return searchFiltered.sorted(using: sortOrder)
    }

    var selectedEntry: HistoryEntry? {
        guard let id = selectedEntryId else { return nil }
        return filteredHistory.first { $0.id == id }
    }

    var body: some View {
        NavigationSplitView {
            historyTable
                .frame(minWidth: 750)
        } detail: {
            detailView
                .frame(minWidth: 350)
        }
        .frame(minWidth: 1200, minHeight: 650)
        .onAppear {
            if let entryId = appState.selectedHistoryEntryId {
                selectedEntryId = entryId
                appState.selectedHistoryEntryId = nil
            }
        }
    }

    private var historyTable: some View {
        Group {
            if appState.violationHistory.isEmpty {
                ContentUnavailableView(
                    "No Credential Accesses",
                    systemImage: "checkmark.shield",
                    description: Text("No credential accesses have been recorded yet.")
                )
            } else {
                Table(filteredHistory, selection: $selectedEntryId, sortOrder: $sortOrder) {
                    TableColumn("Outcome", value: \.userAction.label) { entry in
                        outcomeCell(entry)
                    }
                    .width(min: 85, ideal: 95)

                    TableColumn("Time", value: \.violation.timestamp) { entry in
                        timestampCell(entry)
                    }
                    .width(min: 140, ideal: 170)

                    TableColumn("Process", value: \.violation.processName) { entry in
                        processCell(entry)
                    }
                    .width(min: 140, ideal: 170)

                    TableColumn("Credential", value: \.violation.filePath) { entry in
                        credentialCell(entry)
                    }
                    .width(min: 220, ideal: 300)

                    TableColumn("Rule") { entry in
                        ruleCell(entry)
                    }
                    .width(min: 90, ideal: 110)
                }
                .searchable(text: $searchText, prompt: "Search credential accesses...")
            }
        }
        .navigationTitle("Credential Access History")
        .toolbar {
            toolbarContent
        }
    }

    @ViewBuilder
    private var detailView: some View {
        if let entry = selectedEntry {
            HistoryDetailView(entry: entry)
        } else {
            ContentUnavailableView(
                "Select a Credential Access",
                systemImage: "key.fill",
                description: Text("Select a credential access from the list to see details.")
            )
        }
    }

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        ToolbarItem(placement: .automatic) {
            filterMenu
        }

        ToolbarItem(placement: .primaryAction) {
            Button(action: refreshHistory) {
                Image(systemName: "arrow.clockwise")
            }
            .help("Refresh history")
        }

        ToolbarItem(placement: .primaryAction) {
            Button(action: exportHistory) {
                Image(systemName: "square.and.arrow.up")
            }
            .help("Export history")
        }
    }

    private var filterMenu: some View {
        Menu {
            Toggle("Allowed", isOn: $showAllowed)
            Toggle("Resumed", isOn: $showResumed)
            Toggle("Killed", isOn: $showKilled)
            Toggle("Pending", isOn: $showPending)
            Toggle("Dismissed", isOn: $showDismissed)
            Toggle("Logged", isOn: $showLogged)

            Divider()

            Button("Show All", action: showAllFilters)
            Button("Hide All", action: hideAllFilters)
        } label: {
            Label("Filter", systemImage: "line.3.horizontal.decrease.circle")
        }
        .help("Filter by outcome type")
    }

    private func showAllFilters() {
        showAllowed = true
        showResumed = true
        showKilled = true
        showPending = true
        showDismissed = true
        showLogged = true
    }

    private func hideAllFilters() {
        showAllowed = false
        showResumed = false
        showKilled = false
        showPending = false
        showDismissed = false
        showLogged = false
    }


    // MARK: - Table Cell Views

    private func outcomeCell(_ entry: HistoryEntry) -> some View {
        HStack(spacing: 5) {
            Image(systemName: entry.userAction.icon)
                .foregroundStyle(userActionColor(entry.userAction))
                .font(.system(size: 11))
                .frame(width: 14)
            Text(entry.userAction.label)
                .font(.system(size: 12))
                .foregroundStyle(userActionColor(entry.userAction))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func timestampCell(_ entry: HistoryEntry) -> some View {
        Text(formatCompactTimestamp(entry.violation.timestamp))
            .font(.system(.body, design: .monospaced))
            .help(entry.violation.timestamp.formatted(date: .complete, time: .complete))
    }

    private func formatCompactTimestamp(_ date: Date) -> String {
        let calendar = Calendar.current
        let now = Date()

        if calendar.isDateInToday(date) {
            // Today: just show time
            return date.formatted(date: .omitted, time: .shortened)
        } else if calendar.isDate(date, equalTo: now, toGranularity: .year) {
            // This year: MMM d, HH:mm
            let formatter = DateFormatter()
            formatter.dateFormat = "MMM d, HH:mm"
            return formatter.string(from: date)
        } else {
            // Other years: MMM d yyyy, HH:mm
            let formatter = DateFormatter()
            formatter.dateFormat = "MMM d yyyy, HH:mm"
            return formatter.string(from: date)
        }
    }

    private func processCell(_ entry: HistoryEntry) -> some View {
        HStack(spacing: 6) {
            Circle()
                .fill(signingColor(for: entry.violation))
                .frame(width: 8, height: 8)
                .help(entry.violation.signingStatus.label)
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.violation.processName)
                    .fontWeight(.medium)
                Text("PID \(entry.violation.processPid)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func credentialCell(_ entry: HistoryEntry) -> some View {
        Text(entry.violation.filePath)
            .font(.system(.body, design: .monospaced))
            .lineLimit(1)
            .truncationMode(.middle)
            .help(entry.violation.filePath)
    }

    private func ruleCell(_ entry: HistoryEntry) -> some View {
        Group {
            if let ruleId = entry.violation.ruleId {
                Text(ruleId)
                    .foregroundStyle(.secondary)
            } else {
                Text("—")
                    .foregroundStyle(.tertiary)
            }
        }
    }

    private func isToday(_ date: Date) -> Bool {
        Calendar.current.isDateInToday(date)
    }

    private func formatPrimaryTime(_ date: Date) -> String {
        let formatter = DateFormatter()
        if isToday(date) {
            formatter.dateFormat = "HH:mm:ss"
        } else {
            formatter.dateFormat = "MMM d"
        }
        return formatter.string(from: date)
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

    private func userActionColor(_ action: UserAction) -> Color {
        switch action {
        case .resumed: return .green
        case .killed: return .red
        case .allowed: return .blue
        case .pending: return .orange
        case .dismissed: return .secondary
        case .logged: return .secondary
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
        case .logged: return .gray.opacity(0.1)
        }
    }

    private var foregroundColor: Color {
        switch action {
        case .resumed: return .green
        case .killed: return .red
        case .allowed: return .blue
        case .pending: return .orange
        case .dismissed: return .secondary
        case .logged: return .secondary
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

    /// Find a matching exception for this violation.
    /// Using a computed property ensures SwiftUI tracks appState.exceptions changes.
    private var matchingException: Exception? {
        findMatchingException(exceptions: appState.exceptions, violation: entry.violation)
    }

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
        .navigationTitle("Access Details")
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

                HStack(spacing: 4) {
                    Text(entry.violation.timestamp.formatted(date: .abbreviated, time: .omitted))
                        .foregroundColor(.secondary)
                    Text("at")
                        .foregroundStyle(.tertiary)
                        .font(.caption)
                    Text(entry.violation.timestamp.formatted(date: .omitted, time: .standard))
                        .foregroundColor(.secondary)
                }

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
        if let exception = matchingException {
            // Covered by an exception
            DetailSection(title: "Exception Coverage") {
                HStack(spacing: 8) {
                    Image(systemName: "checkmark.shield.fill")
                        .foregroundStyle(.green)
                    Text("Covered by existing exception")
                        .fontWeight(.medium)
                        .foregroundStyle(.green)
                }
                DetailRow(label: "Pattern", value: exception.filePattern)
                if let processPath = exception.processPath {
                    DetailRow(label: "Process", value: processPath)
                }
                if let signerDesc = exception.signerDescription {
                    DetailRow(label: "Signer", value: signerDesc)
                }
                if exception.isPermanent {
                    DetailRow(label: "Duration", value: "Permanent")
                } else if let remaining = exception.timeRemaining {
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
