import SwiftUI

struct InstallationSuccessView: View {
    let onDismiss: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            // Header with icon
            VStack(spacing: 16) {
                ZStack {
                    Circle()
                        .fill(.green.opacity(0.15))
                        .frame(width: 80, height: 80)

                    Image(systemName: "checkmark.circle.fill")
                        .font(.system(size: 64))
                        .foregroundStyle(.green.gradient)
                        .symbolRenderingMode(.hierarchical)
                }

                Text("Installation Complete")
                    .font(.title2)
                    .fontWeight(.semibold)
            }
            .padding(.top, 32)
            .padding(.bottom, 24)

            // Content
            VStack(alignment: .leading, spacing: 16) {
                Text("The SecretKeeper agent has been successfully installed and is now running.")
                    .font(.body)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)

                VStack(alignment: .leading, spacing: 12) {
                    SuccessStepRow(
                        icon: "checkmark.circle.fill",
                        text: "Agent installed and running",
                        color: .green
                    )

                    SuccessStepRow(
                        icon: "checkmark.circle.fill",
                        text: "Automatic startup enabled",
                        color: .green
                    )

                    SuccessStepRow(
                        icon: "checkmark.circle.fill",
                        text: "Monitoring active",
                        color: .green
                    )
                }
                .padding(.vertical, 8)
            }
            .frame(maxWidth: .infinity)
            .padding(.horizontal, 32)
            .padding(.bottom, 24)

            Divider()

            // Button
            HStack {
                Spacer()
                Button("OK") {
                    onDismiss()
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
            }
            .padding(20)
        }
        .frame(width: 460, height: 380)
        .background(Color(NSColor.windowBackgroundColor))
    }
}

struct SuccessStepRow: View {
    let icon: String
    let text: String
    let color: Color

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .foregroundStyle(color.gradient)
                .font(.system(size: 16))
                .frame(width: 20)

            Text(text)
                .font(.body)
                .foregroundColor(.primary)
        }
    }
}

struct InstallationSuccessView_Previews: PreviewProvider {
    static var previews: some View {
        InstallationSuccessView(onDismiss: {})
    }
}
