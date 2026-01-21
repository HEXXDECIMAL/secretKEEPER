import SwiftUI

struct ViolationHistoryView: View {
    @EnvironmentObject var appState: AppState
    @State private var searchText = ""
    @State private var selectedViolationId: String?
    @State private var sortOrder = [KeyPathComparator(\ViolationEvent.timestamp, order: .reverse)]

    var filteredViolations: [ViolationEvent] {
        if searchText.isEmpty {
            return appState.violationHistory
        }
        return appState.violationHistory.filter { violation in
            violation.filePath.localizedCaseInsensitiveContains(searchText) ||
            violation.processPath.localizedCaseInsensitiveContains(searchText) ||
            (violation.teamId?.localizedCaseInsensitiveContains(searchText) ?? false)
        }
    }

    var selectedViolation: ViolationEvent? {
        guard let id = selectedViolationId else { return nil }
        return filteredViolations.first { $0.id == id }
    }

    var body: some View {
        NavigationSplitView {
            // List view
            Table(filteredViolations, selection: $selectedViolationId, sortOrder: $sortOrder) {
                TableColumn("Time", value: \.timestamp) { violation in
                    Text(formatTime(violation.timestamp))
                        .font(.system(.body, design: .monospaced))
                }
                .width(min: 80, ideal: 100)

                TableColumn("Process") { violation in
                    HStack(spacing: 4) {
                        Circle()
                            .fill(signingColor(for: violation))
                            .frame(width: 8, height: 8)
                        Text(violation.processName)
                            .font(.system(.body, design: .monospaced))
                    }
                }
                .width(min: 120, ideal: 150)

                TableColumn("File") { violation in
                    Text(violation.filePath)
                        .font(.system(.body, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                .width(min: 200)

                TableColumn("Action", value: \.action) { violation in
                    ActionBadge(action: violation.action)
                }
                .width(min: 80, ideal: 90)

                TableColumn("PID", value: \.processPid) { violation in
                    Text("\(violation.processPid)")
                        .font(.system(.body, design: .monospaced))
                        .monospacedDigit()
                }
                .width(min: 60, ideal: 70)
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
                }

                ToolbarItem(placement: .primaryAction) {
                    Button {
                        exportHistory()
                    } label: {
                        Image(systemName: "square.and.arrow.up")
                    }
                }
            }
        } detail: {
            // Detail view
            if let violation = selectedViolation {
                ViolationDetailView(violation: violation)
            } else {
                ContentUnavailableView(
                    "Select a Violation",
                    systemImage: "exclamationmark.triangle",
                    description: Text("Select a violation from the list to see details.")
                )
            }
        }
    }

    private func formatTime(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        return formatter.string(from: date)
    }

    private func signingColor(for violation: ViolationEvent) -> Color {
        switch violation.signingStatus {
        case .platform: return .blue
        case .signed: return .purple
        case .unsigned: return .red
        }
    }

    private func refreshHistory() {
        // Would call IPC to refresh
    }

    private func exportHistory() {
        // Would export to CSV/JSON
    }
}

struct ActionBadge: View {
    let action: String

    var body: some View {
        Text(action)
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

struct ViolationDetailView: View {
    let violation: ViolationEvent

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                // Header
                HStack {
                    VStack(alignment: .leading) {
                        Text(violation.processName)
                            .font(.title2)
                            .fontWeight(.bold)
                        Text(violation.timestamp.formatted())
                            .foregroundColor(.secondary)
                    }
                    Spacer()
                    ActionBadge(action: violation.action)
                    SigningBadge(status: violation.signingStatus)
                }

                Divider()

                // File info
                DetailSection(title: "Protected File") {
                    DetailRow(label: "Path", value: violation.filePath)
                    if let ruleId = violation.ruleId {
                        DetailRow(label: "Rule", value: ruleId)
                    }
                }

                // Process info
                DetailSection(title: "Process Information") {
                    DetailRow(label: "Path", value: violation.processPath)
                    DetailRow(label: "PID", value: "\(violation.processPid)")
                    if let ppid = violation.parentPid {
                        DetailRow(label: "Parent PID", value: "\(ppid)")
                    }
                    if let euid = violation.processEuid {
                        DetailRow(label: "Effective UID", value: "\(euid)")
                    }
                    if let cmdline = violation.processCmdline {
                        DetailRow(label: "Command", value: cmdline)
                    }
                }

                // Signing info
                if violation.teamId != nil || violation.signingId != nil {
                    DetailSection(title: "Code Signing") {
                        if let teamId = violation.teamId {
                            DetailRow(label: "Team ID", value: teamId)
                        }
                        if let signingId = violation.signingId {
                            DetailRow(label: "Signing ID", value: signingId)
                        }
                    }
                }

                // Process tree
                DetailSection(title: "Process Tree") {
                    ProcessTreeView(entries: violation.processTree)
                }

                Spacer()
            }
            .padding()
        }
        .navigationTitle("Violation Details")
    }
}

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
