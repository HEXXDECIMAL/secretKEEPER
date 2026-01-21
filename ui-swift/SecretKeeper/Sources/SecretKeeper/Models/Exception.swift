import Foundation

/// A runtime exception that allows a process to access protected files.
struct Exception: Codable, Identifiable, Hashable {
    let id: Int64
    let processPath: String?
    let codeSigner: String?
    let filePattern: String
    let isGlob: Bool
    let expiresAt: Date?
    let addedBy: String
    let comment: String?
    let createdAt: Date

    enum CodingKeys: String, CodingKey {
        case id
        case processPath = "process_path"
        case codeSigner = "code_signer"
        case filePattern = "file_pattern"
        case isGlob = "is_glob"
        case expiresAt = "expires_at"
        case addedBy = "added_by"
        case comment
        case createdAt = "created_at"
    }

    /// Whether this exception is permanent (no expiration).
    var isPermanent: Bool {
        expiresAt == nil
    }

    /// Whether this exception has expired.
    var isExpired: Bool {
        guard let expires = expiresAt else { return false }
        return Date() > expires
    }

    /// Human-readable description of what this exception allows.
    var description: String {
        var parts: [String] = []

        if let path = processPath {
            parts.append("Process: \(path)")
        }
        if let signer = codeSigner {
            parts.append("Signer: \(signer)")
        }
        parts.append("Files: \(filePattern)")

        return parts.joined(separator: " | ")
    }

    /// Time remaining until expiration.
    var timeRemaining: String? {
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
}

/// Request to add a new exception.
struct AddExceptionRequest: Codable {
    let action = "add_exception"
    let processPath: String?
    let codeSigner: String?
    let filePattern: String
    let isGlob: Bool
    let expiresAt: Date?
    let comment: String?

    enum CodingKeys: String, CodingKey {
        case action
        case processPath = "process_path"
        case codeSigner = "code_signer"
        case filePattern = "file_pattern"
        case isGlob = "is_glob"
        case expiresAt = "expires_at"
        case comment
    }
}
