import Foundation
import SecretKeeperLib
import SwiftUI

/// Central app state, observable across all views.
/// All mutations are automatically dispatched to the main thread for thread safety with SwiftUI.
class AppState: ObservableObject {
    @Published var isConnected: Bool = false
    @Published var agentInstalled: Bool = false
    @Published var agentStatus: AgentStatus?
    @Published var pendingViolations: [ViolationEvent] = []
    @Published var violationHistory: [HistoryEntry] = []
    @Published var exceptions: [Exception] = []
    @Published var categories: [ProtectedCategory] = []
    @Published var totalViolations: Int = 0
    @Published var mode: EnforcementMode = .block

    /// Maximum history entries to retain.
    private let maxHistoryEntries = 500

    /// Ensure a closure runs on the main thread.
    private func onMain(_ action: @escaping () -> Void) {
        if Thread.isMainThread {
            action()
        } else {
            DispatchQueue.main.async(execute: action)
        }
    }

    func clearPendingViolation(_ id: String) {
        onMain {
            self.pendingViolations.removeAll { $0.id == id }
        }
    }

    func setCategoryEnabled(_ categoryId: String, enabled: Bool) {
        onMain {
            if let index = self.categories.firstIndex(where: { $0.id == categoryId }) {
                self.categories[index].enabled = enabled
            }
        }
    }

    /// Add a violation to history when received.
    func addToHistory(_ violation: ViolationEvent) {
        onMain {
            let entry = HistoryEntry(violation: violation, userAction: .pending)
            self.violationHistory.insert(entry, at: 0)
            self.trimHistory()
        }
    }

    /// Record a user action on a violation.
    func recordAction(_ action: UserAction, forViolationId id: String) {
        onMain {
            if let index = self.violationHistory.firstIndex(where: { $0.id == id }) {
                self.violationHistory[index].userAction = action
                self.violationHistory[index].actionTimestamp = Date()
            }
        }
    }

    private func trimHistory() {
        // Called from onMain, so already on main thread
        if violationHistory.count > maxHistoryEntries {
            violationHistory = Array(violationHistory.prefix(maxHistoryEntries))
        }
    }
}

/// A protected file category from the agent.
struct ProtectedCategory: Codable, Identifiable {
    let id: String
    var enabled: Bool
    let patterns: [String]
}

enum EnforcementMode: String, Codable {
    case monitor
    case block
    case bestEffort = "best-effort"
}

/// Agent status information.
struct AgentStatus: Codable {
    let mode: String
    let degradedMode: Bool
    let eventsPending: Int
    let connectedClients: Int
    let uptimeSecs: Int
    let totalViolations: Int

    enum CodingKeys: String, CodingKey {
        case mode
        case degradedMode = "degraded_mode"
        case eventsPending = "events_pending"
        case connectedClients = "connected_clients"
        case uptimeSecs = "uptime_secs"
        case totalViolations = "total_violations"
    }
}
