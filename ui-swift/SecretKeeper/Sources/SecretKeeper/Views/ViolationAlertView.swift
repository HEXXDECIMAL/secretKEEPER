import SwiftUI

struct ViolationAlertView: View {
    @EnvironmentObject var appState: AppState
    let violation: ViolationEvent
    @State private var showAddException = false
    @State private var actionTaken = false
    @Environment(\.dismiss) private var dismiss

    private func closeWindow(withAction: Bool = true) {
        if withAction {
            actionTaken = true
        }
        // Clear from pending violations
        appState.clearPendingViolation(violation.id)
        // Close the window
        if let window = NSApp.keyWindow {
            window.close()
        }
    }

    private func handleDismissWithoutAction() {
        // If no action was taken, mark as dismissed
        if !actionTaken {
            appState.recordAction(.dismissed, forViolationId: violation.id)
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.title)
                    .foregroundColor(.orange)

                VStack(alignment: .leading) {
                    Text("Access Blocked")
                        .font(.headline)
                    Text("Protected file access detected")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }

                Spacer()

                SigningBadge(status: violation.signingStatus)
            }
            .padding()
            .background(Color(NSColor.windowBackgroundColor))

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    // File info
                    InfoSection(title: "Protected File") {
                        MonoText(violation.filePath)
                        if let ruleId = violation.ruleId {
                            Text("Rule: \(ruleId)")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }

                    // Process info
                    InfoSection(title: "Accessing Process") {
                        HStack {
                            MonoText(violation.processPath)
                            Spacer()
                            Text("PID \(violation.processPid)")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        if let cmdline = violation.processCmdline {
                            Text("$ \(cmdline)")
                                .font(.system(.caption, design: .monospaced))
                                .foregroundColor(.secondary)
                                .lineLimit(2)
                        }
                    }

                    // Signing info
                    if violation.teamId != nil || violation.signingId != nil {
                        InfoSection(title: "Code Signing") {
                            if let teamId = violation.teamId {
                                HStack {
                                    Text("Team ID:")
                                        .foregroundColor(.secondary)
                                    MonoText(teamId)
                                }
                            }
                            if let signingId = violation.signingId {
                                HStack {
                                    Text("Signing ID:")
                                        .foregroundColor(.secondary)
                                    MonoText(signingId)
                                }
                            }
                        }
                    }

                    // Process tree
                    InfoSection(title: "Process Tree") {
                        ProcessTreeView(entries: violation.processTree)
                    }
                }
                .padding()
            }

            Divider()

            // Action buttons
            HStack(spacing: 12) {
                // Kill - terminates the stopped process
                Button {
                    if let appDelegate = AppDelegate.shared {
                        appDelegate.handleKillProcess(eventId: violation.id)
                    }
                    closeWindow(withAction: true)
                } label: {
                    Label("Kill", systemImage: "xmark.circle.fill")
                }
                .buttonStyle(.bordered)
                .tint(.red)
                .help("Terminate the stopped process")

                // Resume - allows the process to continue (one-time)
                Button {
                    if let appDelegate = AppDelegate.shared {
                        appDelegate.handleAllowOnce(eventId: violation.id)
                    }
                    closeWindow(withAction: true)
                } label: {
                    Label("Resume", systemImage: "play.circle.fill")
                }
                .buttonStyle(.bordered)
                .tint(.orange)
                .help("Allow this process to continue (one-time)")

                Spacer()

                Button("Add Exception...") {
                    showAddException = true
                }
                .buttonStyle(.bordered)
                .help("Create an exception rule for future access")

                // OK - acknowledge and allow permanently
                Button {
                    if let appDelegate = AppDelegate.shared {
                        appDelegate.handleAllowPermanently(eventId: violation.id)
                    }
                    closeWindow(withAction: true)
                } label: {
                    Label("OK", systemImage: "checkmark.circle.fill")
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
                .help("Allow this process and add a permanent exception")
            }
            .padding()
        }
        .frame(minWidth: 550, minHeight: 450)
        .sheet(isPresented: $showAddException) {
            AddExceptionSheet(violation: violation)
        }
        .onDisappear {
            handleDismissWithoutAction()
        }
    }
}

struct InfoSection<Content: View>: View {
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

struct MonoText: View {
    let text: String

    init(_ text: String) {
        self.text = text
    }

    var body: some View {
        Text(text)
            .font(.system(.body, design: .monospaced))
            .textSelection(.enabled)
    }
}

struct SigningBadge: View {
    let status: SigningStatus

    var body: some View {
        HStack(spacing: 4) {
            Circle()
                .fill(color)
                .frame(width: 8, height: 8)
            Text(status.label)
                .font(.caption)
                .fontWeight(.medium)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(color.opacity(0.2))
        .cornerRadius(4)
    }

    private var color: Color {
        switch status {
        case .platform: return .blue
        case .signed: return .purple
        case .unsigned: return .red
        }
    }
}

struct AddExceptionSheet: View {
    @Environment(\.dismiss) private var dismiss
    let violation: ViolationEvent

    @State private var exceptionType: ExceptionType = .process
    @State private var filePattern: String = ""
    @State private var isGlob = true
    @State private var isPermanent = true
    @State private var expirationHours = 24
    @State private var comment = ""

    enum ExceptionType: String, CaseIterable {
        case process = "Process Path"
        case signer = "Code Signer"
    }

    var body: some View {
        VStack(spacing: 16) {
            Text("Add Exception")
                .font(.headline)

            Form {
                Picker("Exception Type", selection: $exceptionType) {
                    ForEach(ExceptionType.allCases, id: \.self) { type in
                        Text(type.rawValue).tag(type)
                    }
                }
                .pickerStyle(.segmented)

                if exceptionType == .process {
                    LabeledContent("Process") {
                        Text(violation.processPath)
                            .font(.system(.body, design: .monospaced))
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
                        // Default to directory pattern
                        let dir = (violation.filePath as NSString).deletingLastPathComponent
                        filePattern = "\(dir)/*"
                    }

                Toggle("Glob Pattern", isOn: $isGlob)

                Toggle("Permanent", isOn: $isPermanent)

                if !isPermanent {
                    Stepper("Expires in \(expirationHours) hours", value: $expirationHours, in: 1...168)
                }

                TextField("Comment (optional)", text: $comment)
            }
            .padding()

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
        .frame(width: 450)
    }

    private var codeSignerDescription: String {
        // For Apple platform binaries, show a friendly description
        if let signingId = violation.signingId {
            if signingId.hasPrefix("com.apple.") {
                if let teamId = violation.teamId, !teamId.isEmpty {
                    return "\(signingId) (Apple)"
                }
                return "\(signingId) (Apple)"
            }
            // For third-party signed apps
            if let teamId = violation.teamId, !teamId.isEmpty {
                return "\(signingId) (\(teamId))"
            }
            return signingId
        }
        // Fall back to team ID if no signing ID
        if let teamId = violation.teamId, !teamId.isEmpty {
            return teamId
        }
        return "Unsigned"
    }

    private func addException() {
        // Would call IPC to add exception
        // For now, just dismiss
    }
}

