import SwiftUI

struct ExceptionManagerView: View {
    @EnvironmentObject var appState: AppState
    @State private var selectedException: Exception?
    @State private var showAddException = false
    @State private var searchText = ""

    var filteredExceptions: [Exception] {
        if searchText.isEmpty {
            return appState.exceptions
        }
        return appState.exceptions.filter { exception in
            exception.filePattern.localizedCaseInsensitiveContains(searchText) ||
            (exception.processPath?.localizedCaseInsensitiveContains(searchText) ?? false) ||
            (exception.codeSigner?.localizedCaseInsensitiveContains(searchText) ?? false)
        }
    }

    var body: some View {
        NavigationSplitView {
            List(filteredExceptions, selection: $selectedException) { exception in
                ExceptionRow(exception: exception)
            }
            .searchable(text: $searchText, prompt: "Search exceptions...")
            .navigationTitle("Exceptions")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        showAddException = true
                    } label: {
                        Image(systemName: "plus")
                    }
                }

                ToolbarItem(placement: .primaryAction) {
                    Button {
                        refreshExceptions()
                    } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                }
            }
        } detail: {
            if let exception = selectedException {
                ExceptionDetailView(exception: exception) {
                    removeException(exception)
                }
            } else {
                ContentUnavailableView(
                    "Select an Exception",
                    systemImage: "checkmark.shield",
                    description: Text("Select an exception from the list to see details.")
                )
            }
        }
        .sheet(isPresented: $showAddException) {
            NewExceptionSheet()
        }
    }

    private func refreshExceptions() {
        // Would call IPC to refresh
    }

    private func removeException(_ exception: Exception) {
        // Would call IPC to remove
        appState.exceptions.removeAll { $0.id == exception.id }
        selectedException = nil
    }
}

struct ExceptionRow: View {
    let exception: Exception

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                // Type indicator
                HStack(spacing: 4) {
                    if exception.processPath != nil {
                        Label("Process", systemImage: "terminal")
                            .font(.caption)
                            .foregroundColor(.blue)
                    }
                    if exception.codeSigner != nil {
                        Label("Signer", systemImage: "building.2")
                            .font(.caption)
                            .foregroundColor(.purple)
                    }
                }

                // File pattern
                Text(exception.filePattern)
                    .font(.system(.body, design: .monospaced))
                    .lineLimit(1)

                // Expiration
                HStack(spacing: 8) {
                    if exception.isPermanent {
                        Label("Permanent", systemImage: "infinity")
                            .font(.caption)
                            .foregroundColor(.green)
                    } else if let remaining = exception.timeRemaining {
                        Label(remaining, systemImage: "clock")
                            .font(.caption)
                            .foregroundColor(exception.isExpired ? .red : .orange)
                    }

                    Text("by \(exception.addedBy)")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }

            Spacer()

            if exception.isGlob {
                Image(systemName: "asterisk")
                    .foregroundColor(.secondary)
                    .help("Glob pattern")
            }
        }
        .padding(.vertical, 4)
    }
}

struct ExceptionDetailView: View {
    let exception: Exception
    let onDelete: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            // Header
            HStack {
                VStack(alignment: .leading) {
                    Text("Exception #\(exception.id)")
                        .font(.title2)
                        .fontWeight(.bold)
                    Text("Created \(exception.createdAt.formatted())")
                        .foregroundColor(.secondary)
                }
                Spacer()

                if exception.isPermanent {
                    Label("Permanent", systemImage: "infinity")
                        .font(.caption)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(Color.green.opacity(0.2))
                        .foregroundColor(.green)
                        .cornerRadius(4)
                } else if let remaining = exception.timeRemaining {
                    Label(remaining, systemImage: "clock")
                        .font(.caption)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(Color.orange.opacity(0.2))
                        .foregroundColor(.orange)
                        .cornerRadius(4)
                }
            }

            Divider()

            // Details
            VStack(alignment: .leading, spacing: 12) {
                if let processPath = exception.processPath {
                    DetailSection(title: "Process Path") {
                        Text(processPath)
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                    }
                }

                if let codeSigner = exception.codeSigner {
                    DetailSection(title: "Code Signer") {
                        Text(codeSigner)
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                    }
                }

                DetailSection(title: "File Pattern") {
                    HStack {
                        Text(exception.filePattern)
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                        if exception.isGlob {
                            Text("(glob)")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }
                }

                if let comment = exception.comment {
                    DetailSection(title: "Comment") {
                        Text(comment)
                            .foregroundColor(.secondary)
                    }
                }

                DetailSection(title: "Added By") {
                    Text(exception.addedBy)
                }

                if let expiresAt = exception.expiresAt {
                    DetailSection(title: "Expires At") {
                        Text(expiresAt.formatted())
                            .foregroundColor(exception.isExpired ? .red : .primary)
                    }
                }
            }

            Spacer()

            // Actions
            HStack {
                Spacer()
                Button("Remove Exception", role: .destructive) {
                    onDelete()
                }
                .buttonStyle(.bordered)
            }
        }
        .padding()
        .navigationTitle("Exception Details")
    }
}

struct NewExceptionSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var processPath = ""
    @State private var codeSigner = ""
    @State private var filePattern = ""
    @State private var isGlob = true
    @State private var isPermanent = true
    @State private var expirationHours = 24
    @State private var comment = ""
    @State private var useProcessPath = true
    @State private var useCodeSigner = false

    var isValid: Bool {
        !filePattern.isEmpty && (
            (useProcessPath && !processPath.isEmpty) ||
            (useCodeSigner && !codeSigner.isEmpty)
        )
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Text("New Exception")
                    .font(.headline)
                Spacer()
                Button {
                    dismiss()
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundColor(.secondary)
                }
                .buttonStyle(.plain)
            }
            .padding()

            Divider()

            Form {
                Section("Process Identifier") {
                    Toggle("Match by Process Path", isOn: $useProcessPath)
                    if useProcessPath {
                        TextField("Process Path Pattern", text: $processPath)
                            .font(.system(.body, design: .monospaced))
                    }

                    Toggle("Match by Code Signer", isOn: $useCodeSigner)
                    if useCodeSigner {
                        TextField("Team ID", text: $codeSigner)
                            .font(.system(.body, design: .monospaced))
                    }
                }

                Section("File Access") {
                    TextField("File Pattern", text: $filePattern)
                        .font(.system(.body, design: .monospaced))
                    Toggle("Glob Pattern", isOn: $isGlob)
                }

                Section("Expiration") {
                    Toggle("Permanent Exception", isOn: $isPermanent)
                    if !isPermanent {
                        Stepper("Expires in \(expirationHours) hours", value: $expirationHours, in: 1...168)
                    }
                }

                Section("Notes") {
                    TextField("Comment (optional)", text: $comment, axis: .vertical)
                        .lineLimit(3...6)
                }
            }
            .formStyle(.grouped)

            Divider()

            // Actions
            HStack {
                Button("Cancel") {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)

                Spacer()

                Button("Create Exception") {
                    createException()
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(!isValid)
            }
            .padding()
        }
        .frame(width: 500, height: 550)
    }

    private func createException() {
        // Would call IPC to create
        dismiss()
    }
}
