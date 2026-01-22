import Foundation

/// Type of code signer for exceptions.
public enum SignerType: String, Codable, CaseIterable {
    case teamId = "team_id"
    case signingId = "signing_id"
    case adhoc = "adhoc"
    case unsigned = "unsigned"

    public var displayName: String {
        switch self {
        case .teamId: return "Team ID"
        case .signingId: return "Signing ID"
        case .adhoc: return "Adhoc"
        case .unsigned: return "Unsigned"
        }
    }
}

/// A runtime exception that allows a process to access protected files.
public struct Exception: Codable, Identifiable, Hashable {
    public let id: Int64
    public let processPath: String?
    public let signerType: SignerType?
    public let teamId: String?
    public let signingId: String?
    public let filePattern: String
    public let isGlob: Bool
    public let expiresAt: Date?
    public let addedBy: String
    public let comment: String?
    public let createdAt: Date

    public init(
        id: Int64,
        processPath: String?,
        signerType: SignerType?,
        teamId: String?,
        signingId: String?,
        filePattern: String,
        isGlob: Bool,
        expiresAt: Date?,
        addedBy: String,
        comment: String?,
        createdAt: Date
    ) {
        self.id = id
        self.processPath = processPath
        self.signerType = signerType
        self.teamId = teamId
        self.signingId = signingId
        self.filePattern = filePattern
        self.isGlob = isGlob
        self.expiresAt = expiresAt
        self.addedBy = addedBy
        self.comment = comment
        self.createdAt = createdAt
    }

    enum CodingKeys: String, CodingKey {
        case id
        case processPath = "process_path"
        case signerType = "signer_type"
        case teamId = "team_id"
        case signingId = "signing_id"
        case filePattern = "file_pattern"
        case isGlob = "is_glob"
        case expiresAt = "expires_at"
        case addedBy = "added_by"
        case comment
        case createdAt = "created_at"
    }

    /// Whether this exception is permanent (no expiration).
    public var isPermanent: Bool {
        expiresAt == nil
    }

    /// Whether this exception has expired.
    public var isExpired: Bool {
        guard let expires = expiresAt else { return false }
        return Date() > expires
    }

    /// Human-readable description of the signer constraint.
    public var signerDescription: String? {
        guard let type = signerType else { return nil }
        switch type {
        case .teamId:
            if let id = teamId {
                return "Team: \(id)"
            }
            return "Team ID"
        case .signingId:
            if let id = signingId {
                return "Signing: \(id)"
            }
            return "Signing ID"
        case .adhoc:
            if let id = signingId {
                return "Adhoc: \(id)"
            }
            return "Adhoc Signed"
        case .unsigned:
            return "Unsigned"
        }
    }

    /// Human-readable description of what this exception allows.
    public var description: String {
        var parts: [String] = []

        if let path = processPath {
            parts.append("Process: \(path)")
        }
        if let signer = signerDescription {
            parts.append(signer)
        }
        parts.append("Files: \(filePattern)")

        return parts.joined(separator: " | ")
    }

    /// Time remaining until expiration.
    public var timeRemaining: String? {
        guard let expires = expiresAt else { return nil }
        let remaining = expires.timeIntervalSinceNow

        if remaining <= 0 {
            return "Expired"
        }

        let hours = Int(remaining / 3600)
        let minutes = Int((remaining.truncatingRemainder(dividingBy: 3600)) / 60)

        if hours > 24 {
            let days = hours / 24
            return "\(days)d remaining"
        } else if hours > 0 {
            return "\(hours)h \(minutes)m remaining"
        } else {
            return "\(minutes)m remaining"
        }
    }

    /// Code signer for backward compatibility with IPC.
    public var codeSigner: String? {
        // Return the appropriate signer value based on type
        switch signerType {
        case .teamId:
            return teamId
        case .signingId, .adhoc:
            return signingId
        case .unsigned:
            return nil
        case nil:
            return nil
        }
    }
}

/// Request to add a new exception.
public struct AddExceptionRequest: Codable {
    public let action = "add_exception"
    public let processPath: String?
    public let signerType: String?
    public let teamId: String?
    public let signingId: String?
    public let filePattern: String
    public let isGlob: Bool
    public let expiresAt: Date?
    public let comment: String?

    public init(
        processPath: String?,
        signerType: String?,
        teamId: String?,
        signingId: String?,
        filePattern: String,
        isGlob: Bool,
        expiresAt: Date?,
        comment: String?
    ) {
        self.processPath = processPath
        self.signerType = signerType
        self.teamId = teamId
        self.signingId = signingId
        self.filePattern = filePattern
        self.isGlob = isGlob
        self.expiresAt = expiresAt
        self.comment = comment
    }

    enum CodingKeys: String, CodingKey {
        case action
        case processPath = "process_path"
        case signerType = "signer_type"
        case teamId = "team_id"
        case signingId = "signing_id"
        case filePattern = "file_pattern"
        case isGlob = "is_glob"
        case expiresAt = "expires_at"
        case comment
    }
}
