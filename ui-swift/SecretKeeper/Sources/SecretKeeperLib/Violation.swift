import Foundation
import Darwin

/// Current state of a process.
public enum ProcessState {
    case running   // Process is alive and running
    case stopped   // Process is alive but stopped (SIGSTOP)
    case dead      // Process no longer exists

    public var icon: String {
        switch self {
        case .running: return "🟢"
        case .stopped: return "⏹️"
        case .dead: return "💀"
        }
    }

    public var label: String {
        switch self {
        case .running: return "Running"
        case .stopped: return "Stopped"
        case .dead: return "Dead"
        }
    }
}

/// Check the current state of a process by PID using sysctl.
public func processState(for pid: UInt32) -> ProcessState {
    // First check if process exists
    let signalResult = kill(pid_t(pid), 0)
    if signalResult != 0 {
        return .dead
    }

    // Use sysctl to get process info
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, Int32(pid)]
    var info = kinfo_proc()
    var size = MemoryLayout<kinfo_proc>.size

    let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
    if result != 0 || size == 0 {
        // Couldn't get info but process exists - assume running
        return .running
    }

    // Check process status - SSTOP (4) means stopped
    // From sys/proc.h: SSTOP = 4
    let SSTOP: Int8 = 4
    if info.kp_proc.p_stat == SSTOP {
        return .stopped
    }

    return .running
}

/// A violation event from the agent.
public struct ViolationEvent: Codable, Identifiable, Hashable {
    public let id: String
    public let timestamp: Date
    public let ruleId: String?
    public let filePath: String
    public let processPath: String
    public let processPid: UInt32
    public let processCmdline: String?
    public let processEuid: UInt32?
    public let parentPid: UInt32?
    public let teamId: String?
    public let signingId: String?
    public let action: String
    public let processTree: [ProcessTreeEntry]

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

    public init(
        id: String,
        timestamp: Date,
        ruleId: String?,
        filePath: String,
        processPath: String,
        processPid: UInt32,
        processCmdline: String?,
        processEuid: UInt32?,
        parentPid: UInt32?,
        teamId: String?,
        signingId: String?,
        action: String,
        processTree: [ProcessTreeEntry]
    ) {
        self.id = id
        self.timestamp = timestamp
        self.ruleId = ruleId
        self.filePath = filePath
        self.processPath = processPath
        self.processPid = processPid
        self.processCmdline = processCmdline
        self.processEuid = processEuid
        self.parentPid = parentPid
        self.teamId = teamId
        self.signingId = signingId
        self.action = action
        self.processTree = processTree
    }

    /// Process name extracted from path.
    public var processName: String {
        processPath.components(separatedBy: "/").last ?? "Unknown"
    }

    /// File name extracted from path.
    public var fileName: String {
        filePath.components(separatedBy: "/").last ?? "Unknown"
    }

    /// Signing status for UI display.
    public var signingStatus: SigningStatus {
        // Check for Apple platform binaries first
        if let entry = processTree.first, entry.isPlatformBinary {
            return .platform
        }
        // No signing info at all
        if teamId == nil && signingId == nil {
            return .unsigned
        }
        // Has team ID = properly signed by identified developer
        if teamId != nil {
            return .signed
        }
        // Has signingId but no teamId = ad-hoc/self-signed
        return .adhoc
    }
}

/// Process tree entry for EDR-style display.
public struct ProcessTreeEntry: Codable, Identifiable, Hashable {
    public let pid: UInt32
    public let ppid: UInt32?
    public let name: String
    public let path: String
    public let cwd: String?
    public let cmdline: String?
    public let uid: UInt32?
    public let euid: UInt32?
    public let teamId: String?
    public let signingId: String?
    public let isPlatformBinary: Bool
    /// Whether this process is currently stopped (SIGSTOP).
    public let isStopped: Bool

    public var id: UInt32 { pid }

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

    public init(
        pid: UInt32,
        ppid: UInt32?,
        name: String,
        path: String,
        cwd: String?,
        cmdline: String?,
        uid: UInt32?,
        euid: UInt32?,
        teamId: String?,
        signingId: String?,
        isPlatformBinary: Bool,
        isStopped: Bool
    ) {
        self.pid = pid
        self.ppid = ppid
        self.name = name
        self.path = path
        self.cwd = cwd
        self.cmdline = cmdline
        self.uid = uid
        self.euid = euid
        self.teamId = teamId
        self.signingId = signingId
        self.isPlatformBinary = isPlatformBinary
        self.isStopped = isStopped
    }

    public init(from decoder: Decoder) throws {
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
    public var signingStatus: SigningStatus {
        if isPlatformBinary {
            return .platform
        }
        // No signing info at all
        if teamId == nil && signingId == nil {
            return .unsigned
        }
        // Has team ID = properly signed
        if teamId != nil {
            return .signed
        }
        // Has signingId but no teamId = ad-hoc/self-signed
        return .adhoc
    }

    /// Current state of this process (live check).
    public var currentState: ProcessState {
        processState(for: pid)
    }
}

/// Code signing status for color coding.
public enum SigningStatus {
    case platform  // Apple/system binary (blue)
    case signed    // Third-party signed with valid team ID (green)
    case adhoc     // Ad-hoc/self-signed - has signingId but no teamId (orange)
    case unsigned  // No signature at all (red)

    public var color: String {
        switch self {
        case .platform: return "systemBlue"
        case .signed: return "systemGreen"
        case .adhoc: return "systemOrange"
        case .unsigned: return "systemRed"
        }
    }

    public var label: String {
        switch self {
        case .platform: return "Platform"
        case .signed: return "Signed"
        case .adhoc: return "Ad-hoc"
        case .unsigned: return "Unsigned"
        }
    }
}

/// User action taken on a violation.
public enum UserAction: String, Codable {
    case resumed    // User clicked Resume (allow_once)
    case killed     // User clicked Kill
    case allowed    // User clicked OK (allow_permanently)
    case pending    // No action taken yet (process still stopped)
    case dismissed  // User closed without action (process remained stopped)

    public var label: String {
        switch self {
        case .resumed: return "Resumed"
        case .killed: return "Killed"
        case .allowed: return "Allowed"
        case .pending: return "Pending"
        case .dismissed: return "Dismissed"
        }
    }

    public var icon: String {
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
public struct HistoryEntry: Identifiable, Hashable {
    public let id: String
    public let violation: ViolationEvent
    public var userAction: UserAction
    public var actionTimestamp: Date?

    public init(violation: ViolationEvent, userAction: UserAction = .pending) {
        self.id = violation.id
        self.violation = violation
        self.userAction = userAction
        self.actionTimestamp = userAction == .pending ? nil : Date()
    }

    /// Check if the process is still actionable (either process or parent is stopped).
    public var isProcessActionable: Bool {
        guard userAction == .pending || userAction == .dismissed else {
            return false
        }
        // Show kill/resume if either the process or its parent is stopped
        if processState(for: violation.processPid) == .stopped {
            return true
        }
        if let ppid = violation.parentPid, processState(for: ppid) == .stopped {
            return true
        }
        return false
    }

    /// Get current state of the violating process.
    public var processCurrentState: ProcessState {
        processState(for: violation.processPid)
    }

    /// Get current state of the parent process.
    public var parentCurrentState: ProcessState? {
        guard let ppid = violation.parentPid else { return nil }
        return processState(for: ppid)
    }
}
