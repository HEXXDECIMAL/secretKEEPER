import XCTest
@testable import SecretKeeperLib

final class ExceptionTests: XCTestCase {

    // MARK: - Test Helpers

    func makeException(
        id: Int64 = 1,
        processPath: String? = nil,
        signerType: SignerType? = nil,
        teamId: String? = nil,
        signingId: String? = nil,
        filePattern: String = "~/.ssh/*",
        isGlob: Bool = true,
        expiresAt: Date? = nil,
        addedBy: String = "test",
        comment: String? = nil
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
            addedBy: addedBy,
            comment: comment,
            createdAt: Date()
        )
    }

    // MARK: - isPermanent Tests

    func testIsPermanent_withNilExpiration_returnsTrue() {
        let exception = makeException(expiresAt: nil)
        XCTAssertTrue(exception.isPermanent)
    }

    func testIsPermanent_withFutureExpiration_returnsFalse() {
        let exception = makeException(expiresAt: Date().addingTimeInterval(3600))
        XCTAssertFalse(exception.isPermanent)
    }

    func testIsPermanent_withPastExpiration_returnsFalse() {
        let exception = makeException(expiresAt: Date().addingTimeInterval(-3600))
        XCTAssertFalse(exception.isPermanent)
    }

    // MARK: - isExpired Tests

    func testIsExpired_withNilExpiration_returnsFalse() {
        let exception = makeException(expiresAt: nil)
        XCTAssertFalse(exception.isExpired)
    }

    func testIsExpired_withFutureExpiration_returnsFalse() {
        let exception = makeException(expiresAt: Date().addingTimeInterval(3600))
        XCTAssertFalse(exception.isExpired)
    }

    func testIsExpired_withPastExpiration_returnsTrue() {
        let exception = makeException(expiresAt: Date().addingTimeInterval(-3600))
        XCTAssertTrue(exception.isExpired)
    }

    func testIsExpired_justExpired_returnsTrue() {
        let exception = makeException(expiresAt: Date().addingTimeInterval(-1))
        XCTAssertTrue(exception.isExpired)
    }

    func testIsExpired_aboutToExpire_returnsFalse() {
        let exception = makeException(expiresAt: Date().addingTimeInterval(1))
        XCTAssertFalse(exception.isExpired)
    }

    // MARK: - signerDescription Tests

    func testSignerDescription_withNilSignerType_returnsNil() {
        let exception = makeException(signerType: nil)
        XCTAssertNil(exception.signerDescription)
    }

    func testSignerDescription_teamIdWithValue_returnsTeamPrefix() {
        let exception = makeException(signerType: .teamId, teamId: "APPLE123")
        XCTAssertEqual(exception.signerDescription, "Team: APPLE123")
    }

    func testSignerDescription_teamIdWithoutValue_returnsGeneric() {
        let exception = makeException(signerType: .teamId, teamId: nil)
        XCTAssertEqual(exception.signerDescription, "Team ID")
    }

    func testSignerDescription_signingIdWithValue_returnsSigningPrefix() {
        let exception = makeException(signerType: .signingId, signingId: "com.apple.bluetoothd")
        XCTAssertEqual(exception.signerDescription, "Signing: com.apple.bluetoothd")
    }

    func testSignerDescription_signingIdWithoutValue_returnsGeneric() {
        let exception = makeException(signerType: .signingId, signingId: nil)
        XCTAssertEqual(exception.signerDescription, "Signing ID")
    }

    func testSignerDescription_adhocWithValue_returnsAdhocPrefix() {
        let exception = makeException(signerType: .adhoc, signingId: "adhoc-app-id")
        XCTAssertEqual(exception.signerDescription, "Adhoc: adhoc-app-id")
    }

    func testSignerDescription_adhocWithoutValue_returnsGeneric() {
        let exception = makeException(signerType: .adhoc, signingId: nil)
        XCTAssertEqual(exception.signerDescription, "Adhoc Signed")
    }

    func testSignerDescription_unsigned_returnsUnsigned() {
        let exception = makeException(signerType: .unsigned)
        XCTAssertEqual(exception.signerDescription, "Unsigned")
    }

    // MARK: - timeRemaining Tests

    func testTimeRemaining_permanent_returnsNil() {
        let exception = makeException(expiresAt: nil)
        XCTAssertNil(exception.timeRemaining)
    }

    func testTimeRemaining_expired_returnsExpired() {
        let exception = makeException(expiresAt: Date().addingTimeInterval(-3600))
        XCTAssertEqual(exception.timeRemaining, "Expired")
    }

    func testTimeRemaining_lessThanHour_returnsMinutes() {
        let exception = makeException(expiresAt: Date().addingTimeInterval(1800)) // 30 minutes
        let remaining = exception.timeRemaining
        XCTAssertNotNil(remaining)
        XCTAssertTrue(remaining!.contains("m remaining"))
        XCTAssertFalse(remaining!.contains("h"))
    }

    func testTimeRemaining_hoursRemaining_returnsHoursAndMinutes() {
        let exception = makeException(expiresAt: Date().addingTimeInterval(7200)) // 2 hours
        let remaining = exception.timeRemaining
        XCTAssertNotNil(remaining)
        XCTAssertTrue(remaining!.contains("h"))
        XCTAssertTrue(remaining!.contains("m remaining"))
    }

    func testTimeRemaining_daysRemaining_returnsDays() {
        let exception = makeException(expiresAt: Date().addingTimeInterval(172800)) // 48 hours
        let remaining = exception.timeRemaining
        XCTAssertNotNil(remaining)
        XCTAssertTrue(remaining!.contains("d remaining"))
    }

    // MARK: - description Tests

    func testDescription_processPathOnly() {
        let exception = makeException(processPath: "/usr/bin/ssh", filePattern: "~/.ssh/*")
        XCTAssertTrue(exception.description.contains("Process: /usr/bin/ssh"))
        XCTAssertTrue(exception.description.contains("Files: ~/.ssh/*"))
    }

    func testDescription_signerOnly() {
        let exception = makeException(signerType: .teamId, teamId: "APPLE123", filePattern: "~/.ssh/*")
        XCTAssertTrue(exception.description.contains("Team: APPLE123"))
        XCTAssertTrue(exception.description.contains("Files: ~/.ssh/*"))
    }

    func testDescription_processAndSigner() {
        let exception = makeException(
            processPath: "/usr/bin/ssh",
            signerType: .teamId,
            teamId: "APPLE123",
            filePattern: "~/.ssh/*"
        )
        XCTAssertTrue(exception.description.contains("Process: /usr/bin/ssh"))
        XCTAssertTrue(exception.description.contains("Team: APPLE123"))
        XCTAssertTrue(exception.description.contains("Files: ~/.ssh/*"))
    }
}

// MARK: - SignerType Tests

final class SignerTypeTests: XCTestCase {

    func testDisplayName_teamId() {
        XCTAssertEqual(SignerType.teamId.displayName, "Team ID")
    }

    func testDisplayName_signingId() {
        XCTAssertEqual(SignerType.signingId.displayName, "Signing ID")
    }

    func testDisplayName_adhoc() {
        XCTAssertEqual(SignerType.adhoc.displayName, "Adhoc")
    }

    func testDisplayName_unsigned() {
        XCTAssertEqual(SignerType.unsigned.displayName, "Unsigned")
    }

    func testRawValue_snakeCase() {
        XCTAssertEqual(SignerType.teamId.rawValue, "team_id")
        XCTAssertEqual(SignerType.signingId.rawValue, "signing_id")
        XCTAssertEqual(SignerType.adhoc.rawValue, "adhoc")
        XCTAssertEqual(SignerType.unsigned.rawValue, "unsigned")
    }

    func testAllCases() {
        XCTAssertEqual(SignerType.allCases.count, 4)
        XCTAssertTrue(SignerType.allCases.contains(.teamId))
        XCTAssertTrue(SignerType.allCases.contains(.signingId))
        XCTAssertTrue(SignerType.allCases.contains(.adhoc))
        XCTAssertTrue(SignerType.allCases.contains(.unsigned))
    }
}
