import SwiftUI

struct AgentInstallView: View {
    let isInstalled: Bool
    let onInstall: () -> Void
    let onStart: () -> Void
    let onCancel: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            // Header with icon
            VStack(spacing: 16) {
                Image(systemName: "shield.lefthalf.filled.badge.checkmark")
                    .font(.system(size: 64))
                    .foregroundStyle(.blue.gradient)
                    .symbolRenderingMode(.hierarchical)

                Text(isInstalled ? "Agent Not Running" : "Agent Not Installed")
                    .font(.title2)
                    .fontWeight(.semibold)
            }
            .padding(.top, 32)
            .padding(.bottom, 24)

            // Content
            VStack(alignment: .leading, spacing: 16) {
                if isInstalled {
                    Text("The SecretKeeper agent is installed but not currently running.")
                        .font(.body)
                        .foregroundColor(.secondary)

                    Text("The agent needs to be running to protect your secrets from unauthorized access.")
                        .font(.body)
                        .foregroundColor(.secondary)
                } else {
                    Text("SecretKeeper requires a background agent to monitor and protect your sensitive files.")
                        .font(.body)
                        .foregroundColor(.secondary)

                    VStack(alignment: .leading, spacing: 12) {
                        Text("The installation will:")
                            .font(.body)
                            .fontWeight(.medium)

                        InstallationStepRow(
                            icon: "lock.shield",
                            text: "Install the agent to /Library/PrivilegedHelperTools"
                        )

                        InstallationStepRow(
                            icon: "gearshape.2",
                            text: "Create a system daemon to run automatically at startup"
                        )

                        InstallationStepRow(
                            icon: "doc.text",
                            text: "Copy the default configuration file"
                        )
                    }
                    .padding(.vertical, 8)

                    HStack(spacing: 8) {
                        Image(systemName: "key.fill")
                            .foregroundColor(.orange)
                            .font(.system(size: 14))
                        Text("Administrator privileges required")
                            .font(.callout)
                            .foregroundColor(.secondary)
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .background(Color.orange.opacity(0.1))
                    .cornerRadius(8)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 32)
            .padding(.bottom, 24)

            Divider()

            // Buttons
            HStack(spacing: 12) {
                Button("Cancel") {
                    onCancel()
                }
                .keyboardShortcut(.cancelAction)
                .buttonStyle(.plain)
                .foregroundColor(.secondary)
                .padding(.horizontal, 16)
                .padding(.vertical, 8)

                Spacer()

                Button(isInstalled ? "Start Agent" : "Install Agent") {
                    if isInstalled {
                        onStart()
                    } else {
                        onInstall()
                    }
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
            }
            .padding(20)
        }
        .frame(width: 560, height: isInstalled ? 300 : 480)
        .background(Color(NSColor.windowBackgroundColor))
    }
}

struct InstallationStepRow: View {
    let icon: String
    let text: String

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon)
                .foregroundStyle(.blue)
                .font(.system(size: 16))
                .frame(width: 20)

            Text(text)
                .font(.body)
                .foregroundColor(.primary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

struct AgentInstallView_Previews: PreviewProvider {
    static var previews: some View {
        Group {
            AgentInstallView(
                isInstalled: false,
                onInstall: {},
                onStart: {},
                onCancel: {}
            )
            .previewDisplayName("Not Installed")

            AgentInstallView(
                isInstalled: true,
                onInstall: {},
                onStart: {},
                onCancel: {}
            )
            .previewDisplayName("Not Running")
        }
    }
}
