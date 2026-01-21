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
