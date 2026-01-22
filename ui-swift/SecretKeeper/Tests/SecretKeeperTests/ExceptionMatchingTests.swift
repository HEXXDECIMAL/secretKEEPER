import XCTest
@testable import SecretKeeperLib

final class GlobMatchingTests: XCTestCase {

    // MARK: - Basic Glob Tests

    func testMatchesGlob_exactMatch() {
        XCTAssertTrue(matchesGlob(pattern: "~/.ssh/id_rsa", path: "~/.ssh/id_rsa"))
        XCTAssertFalse(matchesGlob(pattern: "~/.ssh/id_rsa", path: "~/.ssh/id_ed25519"))
    }

    func testMatchesGlob_singleStar_matchesWithinDirectory() {
        XCTAssertTrue(matchesGlob(pattern: "~/.ssh/*", path: "~/.ssh/id_rsa"))
        XCTAssertTrue(matchesGlob(pattern: "~/.ssh/*", path: "~/.ssh/id_ed25519"))
        XCTAssertTrue(matchesGlob(pattern: "~/.ssh/*", path: "~/.ssh/config"))
    }

    func testMatchesGlob_singleStar_doesNotCrossDirectories() {
        // Single * should not match path separators
        XCTAssertFalse(matchesGlob(pattern: "~/.ssh/*", path: "~/.ssh/keys/id_rsa"))
    }

    func testMatchesGlob_doubleStar_matchesAnyDepth() {
        XCTAssertTrue(matchesGlob(pattern: "~/.ssh/**", path: "~/.ssh/id_rsa"))
        XCTAssertTrue(matchesGlob(pattern: "~/.ssh/**", path: "~/.ssh/keys/id_rsa"))
        XCTAssertTrue(matchesGlob(pattern: "~/.ssh/**", path: "~/.ssh/deep/nested/key"))
    }

    func testMatchesGlob_doubleStarSlash_matchesPathSegments() {
        XCTAssertTrue(matchesGlob(pattern: "**/id_rsa", path: "~/.ssh/id_rsa"))
        XCTAssertTrue(matchesGlob(pattern: "**/id_rsa", path: "/home/user/.ssh/id_rsa"))
    }

    func testMatchesGlob_wildcardInMiddle() {
        XCTAssertTrue(matchesGlob(pattern: "~/.ssh/id_*", path: "~/.ssh/id_rsa"))
        XCTAssertTrue(matchesGlob(pattern: "~/.ssh/id_*", path: "~/.ssh/id_ed25519"))
        XCTAssertFalse(matchesGlob(pattern: "~/.ssh/id_*", path: "~/.ssh/config"))
    }

    func testMatchesGlob_escapesSpecialCharacters() {
        // Dots should be escaped
        XCTAssertTrue(matchesGlob(pattern: "~/.aws/credentials", path: "~/.aws/credentials"))
        XCTAssertFalse(matchesGlob(pattern: "~/.aws/credentials", path: "~/Xaws/credentials"))
    }

    func testMatchesGlob_emptyPattern() {
        XCTAssertTrue(matchesGlob(pattern: "", path: ""))
        XCTAssertFalse(matchesGlob(pattern: "", path: "~/.ssh/id_rsa"))
    }

    func testMatchesGlob_differentPaths() {
        XCTAssertFalse(matchesGlob(pattern: "~/.ssh/*", path: "~/.aws/credentials"))
        XCTAssertFalse(matchesGlob(pattern: "/etc/*", path: "~/.ssh/id_rsa"))
    }
}

final class ExceptionMatchingLogicTests: XCTestCase {

    // MARK: - Test Helpers

    func makeException(
        id: Int64 = 1,
        processPath: String? = nil,
        signerType: SignerType? = nil,
        teamId: String? = nil,
        signingId: String? = nil,
        filePattern: String = "~/.ssh/*",
        isGlob: Bool = true,
        expiresAt: Date? = nil
    ) -> Exception {
        return Exception(
            id: id,
            processPath: processPath,
            signerType: signerType,
            teamId: teamId,
            signingId: signingId,
            filePattern: filePattern,
            isGlob: isGlob,
            expiresAt: expiresAt,
            addedBy: "test",
            comment: nil,
            createdAt: Date()
        )
    }

    func makeViolation(
        processPath: String = "/usr/bin/cat",
        filePath: String = "~/.ssh/id_rsa",
        teamId: String? = nil,
        signingId: String? = nil,
        isPlatformBinary: Bool = false
    ) -> ViolationEvent {
        let json: [String: Any] = [
            "id": "test-\(UUID().uuidString)",
            "timestamp": ISO8601DateFormatter().string(from: Date()),
            "file_path": filePath,
            "process_path": processPath,
            "process_pid": 1234,
            "team_id": teamId as Any,
            "signing_id": signingId as Any,
            "action": "suspended",
            "process_tree": [[
                "pid": 1234,
                "name": processPath.components(separatedBy: "/").last ?? "unknown",
                "path": processPath,
                "team_id": teamId as Any,
                "signing_id": signingId as Any,
                "is_platform_binary": isPlatformBinary,
                "is_stopped": false
            ]]
        ]

        let data = try! JSONSerialization.data(withJSONObject: json)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try! decoder.decode(ViolationEvent.self, from: data)
    }

    // MARK: - File Pattern Matching

    func testExceptionMatches_globPattern_matches() {
        let exception = makeException(filePattern: "~/.ssh/*", isGlob: true)
        let violation = makeViolation(filePath: "~/.ssh/id_rsa")
        XCTAssertTrue(exceptionMatches(exception: exception, violation: violation))
    }

    func testExceptionMatches_globPattern_noMatch() {
        let exception = makeException(filePattern: "~/.ssh/*", isGlob: true)
        let violation = makeViolation(filePath: "~/.aws/credentials")
        XCTAssertFalse(exceptionMatches(exception: exception, violation: violation))
    }

    func testExceptionMatches_exactPattern_matches() {
        let exception = makeException(filePattern: "~/.ssh/id_rsa", isGlob: false)
        let violation = makeViolation(filePath: "~/.ssh/id_rsa")
        XCTAssertTrue(exceptionMatches(exception: exception, violation: violation))
    }

    func testExceptionMatches_exactPattern_noMatch() {
        let exception = makeException(filePattern: "~/.ssh/id_rsa", isGlob: false)
        let violation = makeViolation(filePath: "~/.ssh/id_ed25519")
        XCTAssertFalse(exceptionMatches(exception: exception, violation: violation))
    }

    // MARK: - Process Path Matching

    func testExceptionMatches_processPath_matches() {
        let exception = makeException(processPath: "/usr/bin/ssh")
        let violation = makeViolation(processPath: "/usr/bin/ssh")
        XCTAssertTrue(exceptionMatches(exception: exception, violation: violation))
    }

    func testExceptionMatches_processPath_noMatch() {
        let exception = makeException(processPath: "/usr/bin/ssh")
        let violation = makeViolation(processPath: "/usr/bin/cat")
        XCTAssertFalse(exceptionMatches(exception: exception, violation: violation))
    }

    func testExceptionMatches_noProcessPath_matchesAny() {
        let exception = makeException(processPath: nil)
        let violation1 = makeViolation(processPath: "/usr/bin/ssh")
        let violation2 = makeViolation(processPath: "/usr/bin/cat")
        XCTAssertTrue(exceptionMatches(exception: exception, violation: violation1))
        XCTAssertTrue(exceptionMatches(exception: exception, violation: violation2))
    }

    // MARK: - Expiration

    func testExceptionMatches_expired_returnsFalse() {
        let exception = makeException(expiresAt: Date().addingTimeInterval(-3600))
        let violation = makeViolation()
        XCTAssertFalse(exceptionMatches(exception: exception, violation: violation))
    }

    func testExceptionMatches_notExpired_canMatch() {
        let exception = makeException(expiresAt: Date().addingTimeInterval(3600))
        let violation = makeViolation()
        XCTAssertTrue(exceptionMatches(exception: exception, violation: violation))
    }

    func testExceptionMatches_permanent_canMatch() {
        let exception = makeException(expiresAt: nil)
        let violation = makeViolation()
        XCTAssertTrue(exceptionMatches(exception: exception, violation: violation))
    }

    // MARK: - Team ID Matching

    func testExceptionMatches_teamId_matches() {
        let exception = makeException(signerType: .teamId, teamId: "APPLE123")
        let violation = makeViolation(teamId: "APPLE123")
        XCTAssertTrue(exceptionMatches(exception: exception, violation: violation))
    }

    func testExceptionMatches_teamId_wrongValue() {
        let exception = makeException(signerType: .teamId, teamId: "APPLE123")
        let violation = makeViolation(teamId: "OTHER456")
        XCTAssertFalse(exceptionMatches(exception: exception, violation: violation))
    }

    func testExceptionMatches_teamId_violationHasNone() {
        let exception = makeException(signerType: .teamId, teamId: "APPLE123")
        let violation = makeViolation(teamId: nil)
        XCTAssertFalse(exceptionMatches(exception: exception, violation: violation))
    }

    func testExceptionMatches_teamId_exceptionHasNone() {
        // signer_type=team_id but team_id=nil should not match
        let exception = makeException(signerType: .teamId, teamId: nil)
        let violation = makeViolation(teamId: "APPLE123")
        XCTAssertFalse(exceptionMatches(exception: exception, violation: violation))
    }

    func testExceptionMatches_teamId_caseSensitive() {
        let exception = makeException(signerType: .teamId, teamId: "APPLE123")
        let violation = makeViolation(teamId: "apple123")
        XCTAssertFalse(exceptionMatches(exception: exception, violation: violation))
    }

    // MARK: - Signing ID Matching

    func testExceptionMatches_signingId_matches() {
        let exception = makeException(signerType: .signingId, signingId: "com.apple.bluetoothd")
        let violation = makeViolation(signingId: "com.apple.bluetoothd", isPlatformBinary: true)
        XCTAssertTrue(exceptionMatches(exception: exception, violation: violation))
    }

    func testExceptionMatches_signingId_wrongValue() {
        let exception = makeException(signerType: .signingId, signingId: "com.apple.bluetoothd")
        let violation = makeViolation(signingId: "com.apple.other", isPlatformBinary: true)
        XCTAssertFalse(exceptionMatches(exception: exception, violation: violation))
    }

    func testExceptionMatches_signingId_violationHasNone() {
        let exception = makeException(signerType: .signingId, signingId: "com.apple.bluetoothd")
        let violation = makeViolation(signingId: nil)
        XCTAssertFalse(exceptionMatches(exception: exception, violation: violation))
    }

    // MARK: - Adhoc Matching

    func testExceptionMatches_adhoc_matchesAdhocProcess() {
        let exception = makeException(signerType: .adhoc, signingId: "adhoc-app-id")
        // Adhoc: has signing_id, no team_id, not platform binary
        let violation = makeViolation(signingId: "adhoc-app-id", isPlatformBinary: false)
        XCTAssertTrue(exceptionMatches(exception: exception, violation: violation))
    }

    func testExceptionMatches_adhoc_doesNotMatchPlatformBinary() {
        let exception = makeException(signerType: .adhoc, signingId: "com.apple.bluetoothd")
        // Platform binary is NOT adhoc
        let violation = makeViolation(signingId: "com.apple.bluetoothd", isPlatformBinary: true)
        XCTAssertFalse(exceptionMatches(exception: exception, violation: violation))
    }

    func testExceptionMatches_adhoc_doesNotMatchSignedProcess() {
        let exception = makeException(signerType: .adhoc, signingId: nil)
        // Signed process (has team_id) is NOT adhoc
        let violation = makeViolation(teamId: "TEAM123", signingId: "com.example.app")
        XCTAssertFalse(exceptionMatches(exception: exception, violation: violation))
    }

    func testExceptionMatches_adhoc_withoutSigningId_matchesAnyAdhoc() {
        let exception = makeException(signerType: .adhoc, signingId: nil)
        let violation = makeViolation(signingId: "any-adhoc-id", isPlatformBinary: false)
        XCTAssertTrue(exceptionMatches(exception: exception, violation: violation))
    }

    // MARK: - Unsigned Matching

    func testExceptionMatches_unsigned_matchesUnsignedProcess() {
        let exception = makeException(signerType: .unsigned)
        let violation = makeViolation(teamId: nil, signingId: nil, isPlatformBinary: false)
        XCTAssertTrue(exceptionMatches(exception: exception, violation: violation))
    }

    func testExceptionMatches_unsigned_doesNotMatchSignedProcess() {
        let exception = makeException(signerType: .unsigned)
        let violation = makeViolation(teamId: "TEAM123")
        XCTAssertFalse(exceptionMatches(exception: exception, violation: violation))
    }

    func testExceptionMatches_unsigned_doesNotMatchAdhocProcess() {
        let exception = makeException(signerType: .unsigned)
        let violation = makeViolation(signingId: "adhoc-id", isPlatformBinary: false)
        XCTAssertFalse(exceptionMatches(exception: exception, violation: violation))
    }

    func testExceptionMatches_unsigned_doesNotMatchPlatformBinary() {
        let exception = makeException(signerType: .unsigned)
        let violation = makeViolation(signingId: "com.apple.xyz", isPlatformBinary: true)
        XCTAssertFalse(exceptionMatches(exception: exception, violation: violation))
    }

    // MARK: - No Signer Requirement

    func testExceptionMatches_noSignerType_matchesAny() {
        let exception = makeException(signerType: nil)

        let signed = makeViolation(teamId: "TEAM123")
        let adhoc = makeViolation(signingId: "adhoc-id", isPlatformBinary: false)
        let unsigned = makeViolation()
        let platform = makeViolation(signingId: "com.apple.x", isPlatformBinary: true)

        XCTAssertTrue(exceptionMatches(exception: exception, violation: signed))
        XCTAssertTrue(exceptionMatches(exception: exception, violation: adhoc))
        XCTAssertTrue(exceptionMatches(exception: exception, violation: unsigned))
        XCTAssertTrue(exceptionMatches(exception: exception, violation: platform))
    }

    // MARK: - Combined Conditions

    func testExceptionMatches_allConditionsMustMatch() {
        let exception = makeException(
            processPath: "/usr/bin/ssh",
            signerType: .teamId,
            teamId: "APPLE123",
            filePattern: "~/.ssh/id_rsa",
            isGlob: false
        )

        // All match
        let goodViolation = makeViolation(
            processPath: "/usr/bin/ssh",
            filePath: "~/.ssh/id_rsa",
            teamId: "APPLE123"
        )
        XCTAssertTrue(exceptionMatches(exception: exception, violation: goodViolation))

        // Wrong process
        let badProcess = makeViolation(
            processPath: "/usr/bin/cat",
            filePath: "~/.ssh/id_rsa",
            teamId: "APPLE123"
        )
        XCTAssertFalse(exceptionMatches(exception: exception, violation: badProcess))

        // Wrong file
        let badFile = makeViolation(
            processPath: "/usr/bin/ssh",
            filePath: "~/.ssh/id_ed25519",
            teamId: "APPLE123"
        )
        XCTAssertFalse(exceptionMatches(exception: exception, violation: badFile))

        // Wrong team
        let badTeam = makeViolation(
            processPath: "/usr/bin/ssh",
            filePath: "~/.ssh/id_rsa",
            teamId: "OTHER456"
        )
        XCTAssertFalse(exceptionMatches(exception: exception, violation: badTeam))
    }

    // MARK: - wouldBeAllowedByExceptions

    func testWouldBeAllowedByExceptions_emptyList_returnsFalse() {
        let violation = makeViolation()
        XCTAssertFalse(wouldBeAllowedByExceptions(exceptions: [], violation: violation))
    }

    func testWouldBeAllowedByExceptions_matchingException_returnsTrue() {
        let exception = makeException(filePattern: "~/.ssh/*", isGlob: true)
        let violation = makeViolation(filePath: "~/.ssh/id_rsa")
        XCTAssertTrue(wouldBeAllowedByExceptions(exceptions: [exception], violation: violation))
    }

    func testWouldBeAllowedByExceptions_noMatchingException_returnsFalse() {
        let exception = makeException(filePattern: "~/.aws/*", isGlob: true)
        let violation = makeViolation(filePath: "~/.ssh/id_rsa")
        XCTAssertFalse(wouldBeAllowedByExceptions(exceptions: [exception], violation: violation))
    }

    func testWouldBeAllowedByExceptions_oneOfManyMatches_returnsTrue() {
        let exceptions = [
            makeException(id: 1, filePattern: "~/.aws/*", isGlob: true),
            makeException(id: 2, filePattern: "~/.ssh/*", isGlob: true),
            makeException(id: 3, filePattern: "~/.gpg/*", isGlob: true)
        ]
        let violation = makeViolation(filePath: "~/.ssh/id_rsa")
        XCTAssertTrue(wouldBeAllowedByExceptions(exceptions: exceptions, violation: violation))
    }

    func testWouldBeAllowedByExceptions_allExpired_returnsFalse() {
        let exceptions = [
            makeException(id: 1, filePattern: "~/.ssh/*", isGlob: true, expiresAt: Date().addingTimeInterval(-3600)),
            makeException(id: 2, filePattern: "~/.ssh/*", isGlob: true, expiresAt: Date().addingTimeInterval(-7200))
        ]
        let violation = makeViolation(filePath: "~/.ssh/id_rsa")
        XCTAssertFalse(wouldBeAllowedByExceptions(exceptions: exceptions, violation: violation))
    }
}
