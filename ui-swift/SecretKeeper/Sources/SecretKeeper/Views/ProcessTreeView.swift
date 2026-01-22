import SecretKeeperLib
import SwiftUI

/// Compact process tree visualization for security analysis.
struct ProcessTreeView: View {
    let entries: [ProcessTreeEntry]

    var body: some View {
        if entries.isEmpty {
            HStack {
                Image(systemName: "questionmark.circle")
                    .foregroundStyle(.secondary)
                Text("Process tree not available")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(.vertical, 8)
        } else {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(Array(entries.enumerated()), id: \.offset) { index, entry in
                    ProcessTreeRow(
                        entry: entry,
                        depth: index,
                        isLast: index == entries.count - 1
                    )
                }
            }
        }
    }
}

struct ProcessTreeRow: View {
    let entry: ProcessTreeEntry
    let depth: Int
    let isLast: Bool

    var body: some View {
        let state = entry.currentState
        HStack(spacing: 0) {
            // Compact tree indent (12px per level)
            if depth > 0 {
                HStack(spacing: 0) {
                    ForEach(0..<depth, id: \.self) { _ in
                        Rectangle()
                            .fill(Color.secondary.opacity(0.2))
                            .frame(width: 1)
                            .padding(.leading, 11)
                    }
                    // Connector line
                    Rectangle()
                        .fill(Color.secondary.opacity(0.3))
                        .frame(width: 8, height: 1)
                }
                .frame(width: CGFloat(depth * 12) + 8)
            }

            // Process info row
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    // State indicator
                    Circle()
                        .fill(stateColor(state))
                        .frame(width: 6, height: 6)

                    // Process name
                    Text(entry.name)
                        .font(.system(.callout, design: .monospaced))
                        .fontWeight(depth == 0 ? .semibold : .regular)

                    // PID
                    Text("(\(entry.pid))")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)

                    // Stopped badge
                    if state == .stopped {
                        Text("STOPPED")
                            .font(.system(.caption2, design: .rounded))
                            .fontWeight(.bold)
                            .foregroundStyle(.white)
                            .padding(.horizontal, 5)
                            .padding(.vertical, 1)
                            .background(Color.red)
                            .cornerRadius(3)
                    }

                    Spacer()
                }

                // Full executable path
                Text(entry.path)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .padding(.leading, 12)

                // Signer info line
                Text(signerDescription)
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.tertiary)
                    .padding(.leading, 12)
            }
            .padding(.vertical, 5)
            .padding(.horizontal, 8)
            .background(rowBackground(state))
        }
    }

    private var signerDescription: String {
        if entry.isPlatformBinary {
            if let signingId = entry.signingId {
                return "\(signingId) (Apple)"
            }
            return "Apple Platform Binary"
        }
        if let teamId = entry.teamId {
            if let signingId = entry.signingId {
                return "\(signingId) (\(teamId))"
            }
            return "Team: \(teamId)"
        }
        if let signingId = entry.signingId {
            return signingId
        }
        return "Unsigned"
    }

    private func stateColor(_ state: ProcessState) -> Color {
        switch state {
        case .running: return .green
        case .stopped: return .red
        case .dead: return .secondary
        }
    }

    private func rowBackground(_ state: ProcessState) -> Color {
        if depth == 0 {
            return state == .stopped ? Color.red.opacity(0.1) : Color.orange.opacity(0.08)
        }
        return state == .stopped ? Color.red.opacity(0.05) : Color.clear
    }
}
