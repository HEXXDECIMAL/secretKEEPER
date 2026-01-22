import Foundation

/// A violation event from the agent.
struct ViolationEvent: Codable, Identifiable, Hashable {
    let id: String
    let timestamp: Date
    let ruleId: String?
    let filePath: String
    let processPath: String
    let processPid: UInt32
    let processCmdline: String?
    let processEuid: UInt32?
    let parentPid: UInt32?
    let teamId: String?
    let signingId: String?
    let action: String
    let processTree: [ProcessTreeEntry]

    enum CodingKeys: String, CodingKey {
        case id
        case timestamp
        case ruleId = "rule_id"
        case filePath = "file_path"
        case processPath = "process_path"
        case processPid = "process_pid"
        case processCmdline = "process_cmdline"
        case processEuid = "process_euid"
        case parentPid = "parent_pid"
        case teamId = "team_id"
        case signingId = "signing_id"
        case action
        case processTree = "process_tree"
    }

    /// Process name extracted from path.
    var processName: String {
        processPath.components(separatedBy: "/").last ?? "Unknown"
    }

    /// File name extracted from path.
    var fileName: String {
        filePath.components(separatedBy: "/").last ?? "Unknown"
    }

    /// Signing status for UI display.
    var signingStatus: SigningStatus {
        if teamId == nil && signingId == nil {
            return .unsigned
        }
        // Check for Apple platform binaries
        if let entry = processTree.first, entry.isPlatformBinary {
            return .platform
        }
        return .signed
    }
}

/// Process tree entry for EDR-style display.
struct ProcessTreeEntry: Codable, Identifiable, Hashable {
    let pid: UInt32
    let ppid: UInt32?
    let name: String
    let path: String
    let cwd: String?
    let cmdline: String?
    let uid: UInt32?
    let euid: UInt32?
    let teamId: String?
    let signingId: String?
    let isPlatformBinary: Bool
    /// Whether this process is currently stopped (SIGSTOP).
    let isStopped: Bool

    var id: UInt32 { pid }

    enum CodingKeys: String, CodingKey {
        case pid
        case ppid
        case name
        case path
        case cwd
        case cmdline
        case uid
        case euid
        case teamId = "team_id"
        case signingId = "signing_id"
        case isPlatformBinary = "is_platform_binary"
        case isStopped = "is_stopped"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        pid = try container.decode(UInt32.self, forKey: .pid)
        ppid = try container.decodeIfPresent(UInt32.self, forKey: .ppid)
        name = try container.decode(String.self, forKey: .name)
        path = try container.decode(String.self, forKey: .path)
        cwd = try container.decodeIfPresent(String.self, forKey: .cwd)
        cmdline = try container.decodeIfPresent(String.self, forKey: .cmdline)
        uid = try container.decodeIfPresent(UInt32.self, forKey: .uid)
        euid = try container.decodeIfPresent(UInt32.self, forKey: .euid)
        teamId = try container.decodeIfPresent(String.self, forKey: .teamId)
        signingId = try container.decodeIfPresent(String.self, forKey: .signingId)
        isPlatformBinary = try container.decodeIfPresent(Bool.self, forKey: .isPlatformBinary) ?? false
        isStopped = try container.decodeIfPresent(Bool.self, forKey: .isStopped) ?? false
    }

    /// Signing status for UI display.
    var signingStatus: SigningStatus {
        if isPlatformBinary {
            return .platform
        }
        if teamId != nil || signingId != nil {
            return .signed
        }
        return .unsigned
    }
}

/// Code signing status for color coding.
enum SigningStatus {
    case platform  // Apple/system binary (blue)
    case signed    // Third-party signed (purple)
    case unsigned  // No signature (red)

    var color: String {
        switch self {
        case .platform: return "systemBlue"
        case .signed: return "systemPurple"
        case .unsigned: return "systemRed"
        }
    }

    var label: String {
        switch self {
        case .platform: return "Platform"
        case .signed: return "Signed"
        case .unsigned: return "Unsigned"
        }
    }
}

/// User action taken on a violation.
enum UserAction: String, Codable {
    case resumed    // User clicked Resume (allow_once)
    case killed     // User clicked Kill
    case allowed    // User clicked OK (allow_permanently)
    case pending    // No action taken yet (process still stopped)
    case dismissed  // User closed without action (process remained stopped)

    var label: String {
        switch self {
        case .resumed: return "Resumed"
        case .killed: return "Killed"
        case .allowed: return "Allowed"
        case .pending: return "Pending"
        case .dismissed: return "Dismissed"
        }
    }

    var icon: String {
        switch self {
        case .resumed: return "play.circle.fill"
        case .killed: return "xmark.circle.fill"
        case .allowed: return "checkmark.circle.fill"
        case .pending: return "pause.circle.fill"
        case .dismissed: return "minus.circle.fill"
        }
    }
}

/// A history entry wrapping a violation event with the user's action.
struct HistoryEntry: Identifiable, Hashable {
    let id: String
    let violation: ViolationEvent
    var userAction: UserAction
    var actionTimestamp: Date?

    init(violation: ViolationEvent, userAction: UserAction = .pending) {
        self.id = violation.id
        self.violation = violation
        self.userAction = userAction
        self.actionTimestamp = userAction == .pending ? nil : Date()
    }

    /// Check if the process is still actionable (alive and stopped).
    var isProcessActionable: Bool {
        guard userAction == .pending || userAction == .dismissed else {
            return false
        }
        return isProcessAlive(pid: violation.processPid)
    }

    /// Check if a process with the given PID is still running.
    private func isProcessAlive(pid: UInt32) -> Bool {
        // kill(pid, 0) returns 0 if process exists and we have permission to signal it
        // Returns -1 with ESRCH if process doesn't exist
        return kill(pid_t(pid), 0) == 0
    }
}
