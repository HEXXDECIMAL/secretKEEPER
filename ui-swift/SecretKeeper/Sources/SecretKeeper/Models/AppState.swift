import Foundation
import SwiftUI

/// Central app state, observable across all views.
class AppState: ObservableObject {
    @Published var isConnected: Bool = false
    @Published var agentInstalled: Bool = false
    @Published var agentStatus: AgentStatus?
    @Published var pendingViolations: [ViolationEvent] = []
    @Published var violationHistory: [ViolationEvent] = []
    @Published var exceptions: [Exception] = []
    @Published var totalViolations: Int = 0
    @Published var mode: EnforcementMode = .block

    func clearPendingViolation(_ id: String) {
        pendingViolations.removeAll { $0.id == id }
    }
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
