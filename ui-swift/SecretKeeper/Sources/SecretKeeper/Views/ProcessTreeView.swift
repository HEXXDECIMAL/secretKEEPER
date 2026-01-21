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
                    HStack {
                        Text(entry.name)
                            .font(.system(.body, design: .monospaced))
                            .fontWeight(.medium)

                        Text("PID \(entry.pid)")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundColor(.secondary)

                        if let ppid = entry.ppid {
                            Text("PPID \(ppid)")
                                .font(.system(.caption, design: .monospaced))
                                .foregroundColor(.secondary)
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

                        if let teamId = entry.teamId {
                            Label(teamId, systemImage: "building.2")
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundColor(.secondary)
                        }
                    }
                }

                Spacer()

                // Signing badge
                SigningBadge(status: entry.signingStatus)
            }
            .padding(.vertical, 6)
            .padding(.horizontal, 8)
        }
        .background(depth == 0 ? Color.orange.opacity(0.1) : Color.clear)
    }

    private var signingColor: Color {
        switch entry.signingStatus {
        case .platform: return .blue
        case .signed: return .purple
        case .unsigned: return .red
        }
    }
}

