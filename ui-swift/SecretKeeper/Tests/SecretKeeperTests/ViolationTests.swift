import XCTest
@testable import SecretKeeperLib

final class ViolationTests: XCTestCase {

    // MARK: - Test Helpers

    func makeProcessTreeEntry(
        pid: UInt32 = 1234,
        ppid: UInt32? = 1,
        name: String = "test",
        path: String = "/usr/bin/test",
        teamId: String? = nil,
        signingId: String? = nil,
        isPlatformBinary: Bool = false,
        isStopped: Bool = false
    ) -> ProcessTreeEntry {
        // We need to decode from JSON since ProcessTreeEntry uses init(from:)
        let json: [String: Any] = [
            "pid": pid,
            "ppid": ppid as Any,
            "name": name,
            "path": path,
            "team_id": teamId as Any,
            "signing_id": signingId as Any,
            "is_platform_binary": isPlatformBinary,
            "is_stopped": isStopped
        ]
        let data = try! JSONSerialization.data(withJSONObject: json)
        return try! JSONDecoder().decode(ProcessTreeEntry.self, from: data)
    }

    func makeViolation(
        processPath: String = "/usr/bin/cat",
        filePath: String = "~/.ssh/id_rsa",
        teamId: String? = nil,
        signingId: String? = nil,
        processTree: [ProcessTreeEntry]? = nil
    ) -> ViolationEvent {
        let tree = processTree ?? [makeProcessTreeEntry(
            path: processPath,
            teamId: teamId,
            signingId: signingId
        )]

        let json: [String: Any] = [
            "id": "test-\(UUID().uuidString)",
            "timestamp": ISO8601DateFormatter().string(from: Date()),
            "file_path": filePath,
            "process_path": processPath,
            "process_pid": 1234,
            "team_id": teamId as Any,
            "signing_id": signingId as Any,
            "action": "suspended",
            "process_tree": tree.map { entry -> [String: Any] in
                [
                    "pid": entry.pid,
                    "ppid": entry.ppid as Any,
                    "name": entry.name,
                    "path": entry.path,
                    "team_id": entry.teamId as Any,
                    "signing_id": entry.signingId as Any,
                    "is_platform_binary": entry.isPlatformBinary,
                    "is_stopped": entry.isStopped
                ]
            }
        ]

        let data = try! JSONSerialization.data(withJSONObject: json)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try! decoder.decode(ViolationEvent.self, from: data)
    }

    // MARK: - processName Tests

    func testProcessName_extractsLastComponent() {
        let violation = makeViolation(processPath: "/usr/bin/ssh")
        XCTAssertEqual(violation.processName, "ssh")
    }

    func testProcessName_handlesSimplePath() {
        let violation = makeViolation(processPath: "cat")
        XCTAssertEqual(violation.processName, "cat")
    }

    // MARK: - fileName Tests

    func testFileName_extractsLastComponent() {
        let violation = makeViolation(filePath: "~/.ssh/id_rsa")
        XCTAssertEqual(violation.fileName, "id_rsa")
    }

    func testFileName_handlesNestedPath() {
        let violation = makeViolation(filePath: "/Users/test/.aws/credentials")
        XCTAssertEqual(violation.fileName, "credentials")
    }

    // MARK: - signingStatus Tests

    func testSigningStatus_platformBinary_returnsPlatform() {
        let entry = makeProcessTreeEntry(
            signingId: "com.apple.bluetoothd",
            isPlatformBinary: true
        )
        let violation = makeViolation(
            signingId: "com.apple.bluetoothd",
            processTree: [entry]
        )
        XCTAssertEqual(violation.signingStatus, .platform)
    }

    func testSigningStatus_withTeamId_returnsSigned() {
        let entry = makeProcessTreeEntry(
            teamId: "APPLE123",
            signingId: "com.example.app",
            isPlatformBinary: false
        )
        let violation = makeViolation(
            teamId: "APPLE123",
            signingId: "com.example.app",
            processTree: [entry]
        )
        XCTAssertEqual(violation.signingStatus, .signed)
    }

    func testSigningStatus_signingIdOnly_returnsAdhoc() {
        let entry = makeProcessTreeEntry(
            signingId: "adhoc-app-id",
            isPlatformBinary: false
        )
        let violation = makeViolation(
            signingId: "adhoc-app-id",
            processTree: [entry]
        )
        XCTAssertEqual(violation.signingStatus, .adhoc)
    }

    func testSigningStatus_noSigningInfo_returnsUnsigned() {
        let entry = makeProcessTreeEntry(isPlatformBinary: false)
        let violation = makeViolation(processTree: [entry])
        XCTAssertEqual(violation.signingStatus, .unsigned)
    }

    func testSigningStatus_platformBinaryTakesPrecedence() {
        // Even with no team_id or signing_id, platform binary flag wins
        let entry = makeProcessTreeEntry(isPlatformBinary: true)
        let violation = makeViolation(processTree: [entry])
        XCTAssertEqual(violation.signingStatus, .platform)
    }
}

// MARK: - ProcessTreeEntry Tests

final class ProcessTreeEntryTests: XCTestCase {

    func makeEntry(
        teamId: String? = nil,
        signingId: String? = nil,
        isPlatformBinary: Bool = false
    ) -> ProcessTreeEntry {
        let json: [String: Any] = [
            "pid": 1234,
            "name": "test",
            "path": "/usr/bin/test",
            "team_id": teamId as Any,
            "signing_id": signingId as Any,
            "is_platform_binary": isPlatformBinary,
            "is_stopped": false
        ]
        let data = try! JSONSerialization.data(withJSONObject: json)
        return try! JSONDecoder().decode(ProcessTreeEntry.self, from: data)
    }

    func testSigningStatus_platformBinary() {
        let entry = makeEntry(isPlatformBinary: true)
        XCTAssertEqual(entry.signingStatus, .platform)
    }

    func testSigningStatus_signed() {
        let entry = makeEntry(teamId: "TEAM123", signingId: "com.example.app")
        XCTAssertEqual(entry.signingStatus, .signed)
    }

    func testSigningStatus_adhoc() {
        let entry = makeEntry(signingId: "adhoc-id")
        XCTAssertEqual(entry.signingStatus, .adhoc)
    }

    func testSigningStatus_unsigned() {
        let entry = makeEntry()
        XCTAssertEqual(entry.signingStatus, .unsigned)
    }

    func testSigningStatus_platformOverridesOther() {
        // Platform binary with team_id should still be platform
        let entry = makeEntry(teamId: "TEAM123", isPlatformBinary: true)
        XCTAssertEqual(entry.signingStatus, .platform)
    }
}

// MARK: - SigningStatus Tests

final class SigningStatusTests: XCTestCase {

    func testColor_values() {
        XCTAssertEqual(SigningStatus.platform.color, "systemBlue")
        XCTAssertEqual(SigningStatus.signed.color, "systemGreen")
        XCTAssertEqual(SigningStatus.adhoc.color, "systemOrange")
        XCTAssertEqual(SigningStatus.unsigned.color, "systemRed")
    }

    func testLabel_values() {
        XCTAssertEqual(SigningStatus.platform.label, "Platform")
        XCTAssertEqual(SigningStatus.signed.label, "Signed")
        XCTAssertEqual(SigningStatus.adhoc.label, "Ad-hoc")
        XCTAssertEqual(SigningStatus.unsigned.label, "Unsigned")
    }
}

// MARK: - HistoryEntry Tests

final class HistoryEntryTests: XCTestCase {

    func makeViolationEvent() -> ViolationEvent {
        let json: [String: Any] = [
            "id": "test-id",
            "timestamp": ISO8601DateFormatter().string(from: Date()),
            "file_path": "~/.ssh/id_rsa",
            "process_path": "/usr/bin/cat",
            "process_pid": 1234,
            "action": "suspended",
            "process_tree": [[
                "pid": 1234,
                "name": "cat",
                "path": "/usr/bin/cat",
                "is_platform_binary": false,
                "is_stopped": true
            ]]
        ]
        let data = try! JSONSerialization.data(withJSONObject: json)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try! decoder.decode(ViolationEvent.self, from: data)
    }

    func testInit_setsIdFromViolation() {
        let violation = makeViolationEvent()
        let entry = HistoryEntry(violation: violation)
        XCTAssertEqual(entry.id, violation.id)
    }

    func testInit_defaultsToPending() {
        let violation = makeViolationEvent()
        let entry = HistoryEntry(violation: violation)
        XCTAssertEqual(entry.userAction, .pending)
    }

    func testInit_pendingHasNilTimestamp() {
        let violation = makeViolationEvent()
        let entry = HistoryEntry(violation: violation, userAction: .pending)
        XCTAssertNil(entry.actionTimestamp)
    }

    func testInit_nonPendingHasTimestamp() {
        let violation = makeViolationEvent()
        let entry = HistoryEntry(violation: violation, userAction: .allowed)
        XCTAssertNotNil(entry.actionTimestamp)
    }

    // Note: Testing isProcessActionable with stopped processes requires live process state
    // which can't be reliably tested in unit tests. The implementation uses sysctl() to
    // check if a real process is stopped (SIGSTOP), which won't work with fake PIDs.
    // Integration tests or manual testing should verify this behavior.

    func testIsProcessActionable_allowedAction_returnsFalse() {
        let violation = makeViolationEvent()
        var entry = HistoryEntry(violation: violation, userAction: .allowed)
        entry.userAction = .allowed
        XCTAssertFalse(entry.isProcessActionable)
    }
}
