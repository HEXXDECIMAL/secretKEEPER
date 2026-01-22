import SwiftUI

/// EDR-style process tree visualization.
/// Shows full chain from violating process to init/launchd.
struct ProcessTreeView: View {
    let entries: [ProcessTreeEntry]

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(Array(entries.enumerated()), id: \.offset) { index, entry in
                ProcessTreeRow(
                    entry: entry,
                    depth: index,
                    isLast: index == entries.count - 1
                )
            }
        }
        .background(Color(NSColor.textBackgroundColor))
        .cornerRadius(4)
    }
}

struct ProcessTreeRow: View {
    let entry: ProcessTreeEntry
    let depth: Int
    let isLast: Bool

    var body: some View {
        HStack(spacing: 0) {
            // Tree lines
            ForEach(0..<depth, id: \.self) { level in
                HStack(spacing: 0) {
                    Rectangle()
                        .fill(Color.secondary.opacity(0.3))
                        .frame(width: 1)
                    Spacer()
                }
                .frame(width: 20)
            }

            // Connector
            if depth > 0 {
                HStack(spacing: 0) {
                    VStack(spacing: 0) {
                        Rectangle()
                            .fill(Color.secondary.opacity(0.3))
                            .frame(width: 1)
                        if isLast {
                            Spacer()
                        }
                    }
                    Rectangle()
                        .fill(Color.secondary.opacity(0.3))
                        .frame(height: 1)
                }
                .frame(width: 20, height: 24)
            }

            // Process info
            HStack(spacing: 8) {
                // Signing indicator
                Circle()
                    .fill(signingColor)
                    .frame(width: 8, height: 8)

                // Process name and path
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(entry.name)
                            .font(.system(.body, design: .monospaced))
                            .fontWeight(.medium)

                        Text("PID \(entry.pid)")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundColor(.secondary)
                            .padding(.horizontal, 4)
                            .padding(.vertical, 1)
                            .background(Color.secondary.opacity(0.1))
                            .cornerRadius(3)

                        if let ppid = entry.ppid {
                            Text("PPID \(ppid)")
                                .font(.system(.caption, design: .monospaced))
                                .foregroundColor(.secondary)
                        }

                        // Stopped badge
                        if entry.isStopped {
                            HStack(spacing: 3) {
                                Image(systemName: "pause.circle.fill")
                                    .font(.caption)
                                Text("STOPPED")
                                    .font(.system(.caption2, design: .monospaced))
                                    .fontWeight(.bold)
                            }
                            .foregroundColor(.red)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Color.red.opacity(0.15))
                            .cornerRadius(4)
                        }
                    }

                    Text(entry.path)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)

                    // Additional info row
                    HStack(spacing: 8) {
                        if let euid = entry.euid {
                            Label("UID \(euid)", systemImage: "person")
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundColor(.secondary)
                        }

                        if let cwd = entry.cwd {
                            Label(cwd, systemImage: "folder")
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundColor(.secondary)
                                .lineLimit(1)
                        }

                        // Code signing info - combined for readability
                        Label(signingDescription, systemImage: "signature")
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundColor(.secondary)
                            .lineLimit(1)
                    }
                }

                Spacer()

                // Signing badge
                SigningBadge(status: entry.signingStatus)
            }
            .padding(.vertical, 6)
            .padding(.horizontal, 8)
        }
        .background(
            depth == 0
                ? (entry.isStopped ? Color.red.opacity(0.1) : Color.orange.opacity(0.1))
                : (entry.isStopped ? Color.red.opacity(0.05) : Color.clear)
        )
    }

    private var signingColor: Color {
        switch entry.signingStatus {
        case .platform: return .blue
        case .signed: return .purple
        case .unsigned: return .red
        }
    }

    private var signingDescription: String {
        // For Apple platform binaries, show a friendly description
        if let signingId = entry.signingId {
            if signingId.hasPrefix("com.apple.") || entry.isPlatformBinary == true {
                return "\(signingId) (Apple)"
            }
            // For third-party signed apps
            if let teamId = entry.teamId, !teamId.isEmpty {
                return "\(signingId) (\(teamId))"
            }
            return signingId
        }
        // Fall back to team ID if no signing ID
        if let teamId = entry.teamId, !teamId.isEmpty {
            return teamId
        }
        return "Unsigned"
    }
}

