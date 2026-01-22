import Foundation

/// Utilities for exception matching logic.
/// These are extracted to enable unit testing.

/// Match a glob pattern against a path.
/// Supports: * (any chars except /), ** (any path segments)
public func matchesGlob(pattern: String, path: String) -> Bool {
    // Build regex pattern piece by piece
    var regex = "^"
    var i = pattern.startIndex

    while i < pattern.endIndex {
        let c = pattern[i]

        if c == "*" {
            let next = pattern.index(after: i)
            if next < pattern.endIndex && pattern[next] == "*" {
                // Found **
                let afterDouble = pattern.index(after: next)
                if afterDouble < pattern.endIndex && pattern[afterDouble] == "/" {
                    // **/ - match any path prefix (including empty)
                    regex += "(.*/)?"
                    i = pattern.index(after: afterDouble)
                    continue
                } else {
                    // ** at end or before non-slash - match anything
                    regex += ".*"
                    i = afterDouble
                    continue
                }
            } else {
                // Single * - match anything except /
                regex += "[^/]*"
                i = next
                continue
            }
        } else if c == "." {
            // Escape dot for regex
            regex += "\\."
        } else if c == "/" || c == "-" || c == "_" || c == "~" || c.isLetter || c.isNumber {
            // Safe characters - use directly
            regex += String(c)
        } else {
            // Escape other characters that might be regex special
            regex += "\\" + String(c)
        }

        i = pattern.index(after: i)
    }

    regex += "$"

    guard let regexObj = try? NSRegularExpression(pattern: regex) else {
        return false
    }

    let range = NSRange(path.startIndex..., in: path)
    return regexObj.firstMatch(in: path, range: range) != nil
}

/// Check if an exception matches a violation event.
/// This consolidates the matching logic used in multiple views.
public func exceptionMatches(
    exception: Exception,
    violation: ViolationEvent
) -> Bool {
    fputs("[exceptionMatches] Checking exception id=\(exception.id) pattern=\(exception.filePattern) signerType=\(exception.signerType?.rawValue ?? "nil") teamId=\(exception.teamId ?? "nil") signingId=\(exception.signingId ?? "nil")\n", stderr)
    fputs("[exceptionMatches] Against violation file=\(violation.filePath) teamId=\(violation.teamId ?? "nil") signingId=\(violation.signingId ?? "nil")\n", stderr)

    // Skip expired exceptions
    if exception.isExpired {
        fputs("[exceptionMatches] SKIP: expired\n", stderr)
        return false
    }

    // Check if file pattern matches
    let fileMatches: Bool
    if exception.isGlob {
        fileMatches = matchesGlob(pattern: exception.filePattern, path: violation.filePath)
    } else {
        fileMatches = exception.filePattern == violation.filePath
    }
    if !fileMatches {
        fputs("[exceptionMatches] SKIP: file pattern no match\n", stderr)
        return false
    }
    fputs("[exceptionMatches] File pattern matched\n", stderr)

    // Check process path if specified
    if let exceptionPath = exception.processPath {
        if exceptionPath != violation.processPath {
            fputs("[exceptionMatches] SKIP: process path mismatch \(exceptionPath) vs \(violation.processPath)\n", stderr)
            return false
        }
        fputs("[exceptionMatches] Process path matched\n", stderr)
    }

    // Check signer if specified - must match Rust's strict matching
    if let signerType = exception.signerType {
        switch signerType {
        case .teamId:
            // Both must have matching team_id
            guard let expectedTeam = exception.teamId,
                  let actualTeam = violation.teamId,
                  expectedTeam == actualTeam else {
                fputs("[exceptionMatches] SKIP: teamId mismatch expected=\(exception.teamId ?? "nil") actual=\(violation.teamId ?? "nil")\n", stderr)
                return false
            }
            fputs("[exceptionMatches] Team ID matched: \(expectedTeam)\n", stderr)
        case .signingId:
            // Both must have matching signing_id
            guard let expectedSigning = exception.signingId,
                  let actualSigning = violation.signingId,
                  expectedSigning == actualSigning else {
                fputs("[exceptionMatches] SKIP: signingId mismatch expected=\(exception.signingId ?? "nil") actual=\(violation.signingId ?? "nil")\n", stderr)
                return false
            }
            fputs("[exceptionMatches] Signing ID matched: \(expectedSigning)\n", stderr)
        case .adhoc:
            // Must be adhoc (use signingStatus which checks platform_binary)
            if violation.signingStatus != .adhoc {
                fputs("[exceptionMatches] SKIP: not adhoc, status=\(violation.signingStatus)\n", stderr)
                return false
            }
            // If exception specifies signing_id, it must match
            if let expectedSigning = exception.signingId,
               violation.signingId != expectedSigning {
                fputs("[exceptionMatches] SKIP: adhoc signingId mismatch\n", stderr)
                return false
            }
            fputs("[exceptionMatches] Adhoc matched\n", stderr)
        case .unsigned:
            // Must be unsigned (no signing info at all)
            if violation.signingStatus != .unsigned {
                fputs("[exceptionMatches] SKIP: not unsigned, status=\(violation.signingStatus)\n", stderr)
                return false
            }
            fputs("[exceptionMatches] Unsigned matched\n", stderr)
        }
    }

    fputs("[exceptionMatches] MATCH!\n", stderr)
    return true
}

/// Check if any exception in the list would allow the given violation.
public func wouldBeAllowedByExceptions(
    exceptions: [Exception],
    violation: ViolationEvent
) -> Bool {
    return exceptions.contains { exception in
        exceptionMatches(exception: exception, violation: violation)
    }
}

/// Find the first exception that would cover the given violation.
/// Returns nil if no exception matches.
public func findMatchingException(
    exceptions: [Exception],
    violation: ViolationEvent
) -> Exception? {
    return exceptions.first { exception in
        exceptionMatches(exception: exception, violation: violation)
    }
}
