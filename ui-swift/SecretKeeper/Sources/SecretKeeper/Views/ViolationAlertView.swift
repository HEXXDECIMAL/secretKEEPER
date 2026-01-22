import SwiftUI

struct ViolationAlertView: View {
    @EnvironmentObject var appState: AppState
    let violation: ViolationEvent
    @State private var showAddException = false
    @State private var actionTaken = false

    private func closeWindow(withAction: Bool = true) {
        if withAction {
            actionTaken = true
        }
        let window = NSApp.keyWindow
        appState.clearPendingViolation(violation.id)
        DispatchQueue.main.async {
            window?.close()
        }
    }

    private func handleDismissWithoutAction() {
        if !actionTaken {
            appState.recordAction(.dismissed, forViolationId: violation.id)
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header - focused on what happened
            VStack(spacing: 12) {
                HStack(spacing: 12) {
                    Image(systemName: "hand.raised.fill")
                        .font(.system(size: 32))
                        .foregroundStyle(.orange)

                    VStack(alignment: .leading, spacing: 2) {
                        Text(violation.processName)
                            .font(.title2)
                            .fontWeight(.semibold)
                        Text("attempted to access a protected file")
                            .foregroundStyle(.secondary)
                    }

                    Spacer()
                }

                // The key info: what file was accessed
                HStack {
                    Image(systemName: "doc.badge.gearshape.fill")
                        .foregroundStyle(.secondary)
                    Text(violation.filePath)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                        .lineLimit(2)
                        .truncationMode(.middle)
                    Spacer()
                }
                .padding(10)
                .background(Color(NSColor.controlBackgroundColor))
                .cornerRadius(6)
            }
            .padding()
            .background(Color(NSColor.windowBackgroundColor))

            Divider()

            // Details
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    // Process details - the security-relevant info
                    GroupBox {
                        VStack(alignment: .leading, spacing: 10) {
                            InfoRow(label: "Path", value: violation.processPath)
                            InfoRow(label: "PID", value: "\(violation.processPid)")
                            if let ppid = violation.parentPid {
                                InfoRow(label: "Parent PID", value: "\(ppid)")
                            }
                            if let cmdline = violation.processCmdline {
                                InfoRow(label: "Command", value: cmdline)
                            }
                            if let ruleId = violation.ruleId {
                                InfoRow(label: "Matched Rule", value: ruleId)
                            }
                        }
                    } label: {
                        Label("Process", systemImage: "terminal")
                            .font(.headline)
                    }

                    // Code signing - important for trust decisions
                    GroupBox {
                        VStack(alignment: .leading, spacing: 10) {
                            HStack {
                                Text("Status")
                                    .frame(width: 80, alignment: .trailing)
                                    .foregroundStyle(.secondary)
                                SigningIndicator(status: violation.signingStatus)
                                Spacer()
                            }
                            if let teamId = violation.teamId {
                                InfoRow(label: "Team ID", value: teamId)
                            }
                            if let signingId = violation.signingId {
                                InfoRow(label: "Signing ID", value: signingId)
                            }
                        }
                    } label: {
                        Label("Code Signing", systemImage: "signature")
                            .font(.headline)
                    }

                    // Process tree - compact version
                    if !violation.processTree.isEmpty {
                        GroupBox {
                            ProcessTreeView(entries: violation.processTree)
                        } label: {
                            Label("Process Tree", systemImage: "arrow.triangle.branch")
                                .font(.headline)
                        }
                    }
                }
                .padding()
            }

            Divider()

            // Actions - clear and unambiguous
            HStack(spacing: 12) {
                Button(role: .destructive) {
                    AppDelegate.shared?.handleKillProcess(eventId: violation.id)
                    closeWindow(withAction: true)
                } label: {
                    Text("Terminate")
                        .frame(minWidth: 70)
                }
                .help("Kill the stopped process")

                Button {
                    AppDelegate.shared?.handleAllowOnce(eventId: violation.id)
                    closeWindow(withAction: true)
                } label: {
                    Text("Allow Once")
                        .frame(minWidth: 70)
                }
                .help("Resume the process (one-time)")

                Spacer()

                Button("Add Exception...") {
                    showAddException = true
                }

                Button {
                    AppDelegate.shared?.handleAllowPermanently(eventId: violation.id)
                    closeWindow(withAction: true)
                } label: {
                    Text("Allow Always")
                        .frame(minWidth: 80)
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
                .help("Allow and add permanent exception")
            }
            .padding()
        }
        .frame(width: 680, height: 620)
        .sheet(isPresented: $showAddException) {
            AddExceptionSheet(violation: violation)
        }
        .onDisappear {
            handleDismissWithoutAction()
        }
    }
}

// MARK: - Supporting Views

struct InfoRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack(alignment: .top) {
            Text(label)
                .frame(width: 80, alignment: .trailing)
                .foregroundStyle(.secondary)
            Text(value)
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
                .lineLimit(2)
            Spacer()
        }
    }
}

struct SigningIndicator: View {
    let status: SigningStatus

    var body: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(color)
                .frame(width: 8, height: 8)
            Text(status.label)
                .fontWeight(.medium)
        }
    }

    private var color: Color {
        switch status {
        case .platform: return .blue
        case .signed: return .green
        case .unsigned: return .red
        }
    }
}

struct SigningBadge: View {
    let status: SigningStatus

    var body: some View {
        HStack(spacing: 4) {
            Circle()
                .fill(color)
                .frame(width: 6, height: 6)
            Text(status.label)
                .font(.caption2)
                .fontWeight(.medium)
        }
        .padding(.horizontal, 6)
        .padding(.vertical, 3)
        .background(color.opacity(0.15))
        .cornerRadius(4)
    }

    private var color: Color {
        switch status {
        case .platform: return .blue
        case .signed: return .green
        case .unsigned: return .red
        }
    }
}

// MARK: - Add Exception Sheet

struct AddExceptionSheet: View {
    @Environment(\.dismiss) private var dismiss
    let violation: ViolationEvent

    @State private var exceptionType: ExceptionType = .process
    @State private var filePattern: String = ""
    @State private var isPermanent = true
    @State private var expirationHours = 24

    enum ExceptionType: String, CaseIterable {
        case process = "Process"
        case signer = "Code Signer"
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header
            VStack(spacing: 4) {
                Text("Add Exception")
                    .font(.headline)
                Text("Allow this process to access matching files")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            .padding()

            Divider()

            Form {
                Picker("Match by", selection: $exceptionType) {
                    ForEach(ExceptionType.allCases, id: \.self) { type in
                        Text(type.rawValue).tag(type)
                    }
                }
                .pickerStyle(.segmented)

                if exceptionType == .process {
                    LabeledContent("Process Path") {
                        Text(violation.processPath)
                            .font(.system(.body, design: .monospaced))
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                } else {
                    LabeledContent("Code Signer") {
                        Text(codeSignerDescription)
                            .font(.system(.body, design: .monospaced))
                    }
                }

                TextField("File Pattern", text: $filePattern)
                    .font(.system(.body, design: .monospaced))
                    .onAppear {
                        let dir = (violation.filePath as NSString).deletingLastPathComponent
                        filePattern = "\(dir)/*"
                    }

                Toggle("Permanent exception", isOn: $isPermanent)

                if !isPermanent {
                    Stepper("Expires in \(expirationHours) hours", value: $expirationHours, in: 1...168)
                }
            }
            .formStyle(.grouped)

            Divider()

            HStack {
                Button("Cancel") {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)

                Spacer()

                Button("Add Exception") {
                    addException()
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
            }
            .padding()
        }
        .frame(width: 420)
    }

    private var codeSignerDescription: String {
        if let signingId = violation.signingId {
            if let teamId = violation.teamId, !teamId.isEmpty {
                return "\(teamId) (\(signingId))"
            }
            return signingId
        }
        if let teamId = violation.teamId, !teamId.isEmpty {
            return teamId
        }
        return "Unsigned"
    }

    private func addException() {
        let expiresAt: Date? = isPermanent ? nil : Date().addingTimeInterval(TimeInterval(expirationHours * 3600))
        let processPath: String? = exceptionType == .process ? violation.processPath : nil
        let codeSigner: String? = exceptionType == .signer ? (violation.teamId ?? violation.signingId) : nil

        AppDelegate.shared?.ipcClient?.addException(
            processPath: processPath,
            codeSigner: codeSigner,
            filePattern: filePattern,
            isGlob: filePattern.contains("*"),
            expiresAt: expiresAt,
            comment: nil
        )

        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
            AppDelegate.shared?.ipcClient?.getExceptions()
        }
    }
}
