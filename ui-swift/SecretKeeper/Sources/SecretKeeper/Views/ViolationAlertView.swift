import SecretKeeperLib
import SwiftUI

struct ViolationAlertView: View {
    @EnvironmentObject var appState: AppState
    let violation: ViolationEvent
    @State private var showAddException = false
    @State private var actionTaken = false

    /// Check if this violation is pending (process stopped, awaiting user action).
    /// If not pending, it's a historical view and action buttons should be disabled.
    private var isPending: Bool {
        appState.pendingViolations.contains { $0.id == violation.id }
    }

    /// Find a matching exception for this violation.
    /// Using a computed property ensures SwiftUI tracks appState.exceptions changes.
    private var matchingException: Exception? {
        findMatchingException(exceptions: appState.exceptions, violation: violation)
    }

    /// Find a stopped parent process that can be resumed.
    /// Returns the PID of the first stopped process in the tree (excluding the violator itself).
    private var stoppedParentPid: UInt32? {
        // Check parent PID first
        if let ppid = violation.parentPid, ppid > 1 {
            if processState(for: ppid) == .stopped {
                return ppid
            }
        }
        // Also check process tree for any stopped parent
        for entry in violation.processTree.dropFirst() {  // Skip first entry (the violator)
            if entry.pid > 1 && entry.currentState == .stopped {
                return entry.pid
            }
        }
        return nil
    }

    /// Perform an action safely by deferring everything to avoid use-after-free crashes.
    /// The action closure receives the violation ID.
    private func performAction(_ action: @escaping (String) -> Void) {
        // Capture everything we need before any view changes
        let violationId = violation.id
        let window = NSApp.keyWindow

        // Mark action as taken immediately (synchronously)
        actionTaken = true

        // CRITICAL: Disconnect the SwiftUI view hierarchy BEFORE closing.
        // This forces SwiftUI to tear down immediately, ensuring no dangling
        // observers remain subscribed to @Published properties when we later
        // modify state. Without this, the partially-deallocated view hierarchy
        // can receive Combine notifications during Core Animation cleanup,
        // causing NSConcretePointerArray use-after-free crashes.
        window?.contentView = nil

        // Use orderOut to close WITHOUT animation - this prevents use-after-free
        // crashes in _NSWindowTransformAnimation when SwiftUI tears down the view
        // hierarchy while an animation block still holds references.
        window?.orderOut(nil)

        // Wait for window/view cleanup before modifying state.
        // This delay lets Core Animation and SwiftUI fully tear down the view
        // hierarchy before we trigger any @Published changes. 150ms is enough
        // for complex view hierarchies while not being noticeable to users.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) {
            // Now safe to perform action (IPC call + state modification)
            action(violationId)

            // Clear pending violation after additional delay
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) { [weak appState] in
                appState?.clearPendingViolation(violationId)
            }
        }
    }

    private func handleDismissWithoutAction() {
        // Only record dismissal for pending violations that were closed without action.
        // Historical violations already have their action recorded, and calling
        // recordAction during view deallocation can cause crashes.
        guard !actionTaken && isPending else { return }

        // Capture violation ID before any async work
        let violationId = violation.id

        // Defer the state modification to avoid crashes during view deallocation.
        // Use 150ms delay to ensure SwiftUI view hierarchy is fully torn down.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) { [weak appState] in
            appState?.recordAction(.dismissed, forViolationId: violationId)
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

                // Show exception coverage status (uses computed property for proper SwiftUI updates)
                if let exception = matchingException {
                    HStack(spacing: 8) {
                        Image(systemName: "checkmark.shield.fill")
                            .foregroundStyle(.green)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Covered by existing exception")
                                .fontWeight(.medium)
                            Text(exception.filePattern)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                    }
                    .padding(10)
                    .background(Color.green.opacity(0.1))
                    .cornerRadius(6)
                } else {
                    HStack(spacing: 8) {
                        Image(systemName: "exclamationmark.shield.fill")
                            .foregroundStyle(.orange)
                        Text("Not covered by any exception")
                            .fontWeight(.medium)
                        Spacer()
                    }
                    .padding(10)
                    .background(Color.orange.opacity(0.1))
                    .cornerRadius(6)
                }
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
                            InfoRow(label: "PID", value: String(violation.processPid))
                            if let ppid = violation.parentPid {
                                InfoRow(label: "Parent PID", value: String(ppid))
                            }
                            if let cmdline = violation.processCmdline {
                                InfoRow(label: "Command", value: cmdline)
                            }
                            if let ruleId = violation.ruleId {
                                InfoRow(label: "Matched Rule", value: ruleId)
                            }
                        }
                    } label: {
                        Text("Process")
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
                        Text("Code Signing")
                            .font(.headline)
                    }

                    // Process tree - compact version
                    if !violation.processTree.isEmpty {
                        GroupBox {
                            ProcessTreeView(entries: violation.processTree)
                        } label: {
                            Text("Process Tree")
                                .font(.headline)
                        }
                    }
                }
                .padding()
            }

            Divider()

            // Actions - clear and unambiguous
            HStack(spacing: 12) {
                if isPending {
                    Button(role: .destructive) {
                        performAction { AppDelegate.shared?.handleKillProcess(eventId: $0) }
                    } label: {
                        Text("Terminate")
                            .frame(minWidth: 70)
                    }
                    .help("Kill the stopped process")

                    Button {
                        performAction { AppDelegate.shared?.handleAllowOnce(eventId: $0) }
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
                        performAction { AppDelegate.shared?.handleAllowPermanently(eventId: $0) }
                    } label: {
                        Text("Allow Always")
                            .frame(minWidth: 80)
                    }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .help("Allow and add permanent exception")
                } else {
                    // Historical view - show resolved status or stopped parent warning
                    if let stoppedPid = stoppedParentPid {
                        // Parent process is still stopped - offer to resume it
                        HStack(spacing: 6) {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundStyle(.orange)
                            Text("Parent process (PID \(stoppedPid)) is still stopped")
                                .foregroundStyle(.secondary)
                        }

                        Spacer()

                        Button {
                            performAction { violationId in
                                AppDelegate.shared?.handleResumeProcess(pid: stoppedPid, forViolationId: violationId)
                            }
                        } label: {
                            Text("Resume Parent")
                                .frame(minWidth: 90)
                        }
                        .help("Send SIGCONT to resume the stopped parent process")

                        Button("Add Exception...") {
                            showAddException = true
                        }

                        Button("Close") {
                            // Disconnect SwiftUI before closing to prevent observer crashes
                            if let window = NSApp.keyWindow {
                                window.contentView = nil
                                window.orderOut(nil)
                            } else if let window = NSApp.windows.first(where: { $0.title.contains("Violation") }) {
                                window.contentView = nil
                                window.orderOut(nil)
                            }
                        }
                        .keyboardShortcut(.defaultAction)
                    } else {
                        // Fully resolved - no stopped processes
                        HStack(spacing: 6) {
                            Image(systemName: "clock.badge.checkmark")
                                .foregroundStyle(.secondary)
                            Text("This violation has already been resolved")
                                .foregroundStyle(.secondary)
                        }

                        Spacer()

                        Button("Add Exception...") {
                            showAddException = true
                        }

                        Button("Close") {
                            // Disconnect SwiftUI before closing to prevent observer crashes
                            if let window = NSApp.keyWindow {
                                window.contentView = nil
                                window.orderOut(nil)
                            } else if let window = NSApp.windows.first(where: { $0.title.contains("Violation") }) {
                                window.contentView = nil
                                window.orderOut(nil)
                            }
                        }
                        .keyboardShortcut(.defaultAction)
                    }
                }
            }
            .padding()
        }
        .frame(width: 680, height: 680)
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
                .frame(width: 90, alignment: .trailing)
                .foregroundStyle(.secondary)
                .lineLimit(1)
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
        case .adhoc: return .orange
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
        case .adhoc: return .orange
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
                    // Capture all needed values before dismiss
                    let expiresAt: Date? = isPermanent ? nil : Date().addingTimeInterval(TimeInterval(expirationHours * 3600))
                    let processPath: String? = exceptionType == .process ? violation.processPath : nil
                    let pattern = filePattern
                    let isGlob = filePattern.contains("*")

                    // Determine signer type and values based on what the violation has
                    var signerType: String? = nil
                    var teamId: String? = nil
                    var signingId: String? = nil

                    if exceptionType == .signer {
                        // Prefer team_id if available (more reliable), otherwise signing_id
                        if let team = violation.teamId, !team.isEmpty {
                            signerType = "team_id"
                            teamId = team
                        } else if let signing = violation.signingId, !signing.isEmpty {
                            signerType = "signing_id"
                            signingId = signing
                        }
                    }

                    fputs("[AddExceptionSheet] Adding exception: processPath=\(processPath ?? "nil") signerType=\(signerType ?? "nil") teamId=\(teamId ?? "nil") signingId=\(signingId ?? "nil") pattern=\(pattern)\n", stderr)

                    // Dismiss first, then do work in next run loop
                    dismiss()

                    DispatchQueue.main.async {
                        AppDelegate.shared?.ipcClient?.addException(
                            processPath: processPath,
                            signerType: signerType,
                            teamId: teamId,
                            signingId: signingId,
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

}
