import XCTest
@testable import SecretKeeperLib

final class ExceptionCodingTests: XCTestCase {

    func testEncode_thenDecode_roundtrip() throws {
        let original = Exception(
            id: 42,
            processPath: "/usr/bin/ssh",
            signerType: .teamId,
            teamId: "APPLE123",
            signingId: nil,
            filePattern: "~/.ssh/*",
            isGlob: true,
            expiresAt: Date(timeIntervalSince1970: 1700000000),
            addedBy: "user",
            comment: "Test comment",
            createdAt: Date(timeIntervalSince1970: 1699000000)
        )

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(original)

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let decoded = try decoder.decode(Exception.self, from: data)

        XCTAssertEqual(decoded.id, original.id)
        XCTAssertEqual(decoded.processPath, original.processPath)
        XCTAssertEqual(decoded.signerType, original.signerType)
        XCTAssertEqual(decoded.teamId, original.teamId)
        XCTAssertEqual(decoded.signingId, original.signingId)
        XCTAssertEqual(decoded.filePattern, original.filePattern)
        XCTAssertEqual(decoded.isGlob, original.isGlob)
        XCTAssertEqual(decoded.addedBy, original.addedBy)
        XCTAssertEqual(decoded.comment, original.comment)
    }

    func testDecode_fromSnakeCaseJSON() throws {
        let json = """
        {
            "id": 1,
            "process_path": "/usr/bin/test",
            "signer_type": "signing_id",
            "team_id": null,
            "signing_id": "com.apple.bluetoothd",
            "file_pattern": "~/.ssh/*",
            "is_glob": true,
            "expires_at": null,
            "added_by": "test",
            "comment": null,
            "created_at": "2024-01-01T00:00:00Z"
        }
        """

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let exception = try decoder.decode(Exception.self, from: json.data(using: .utf8)!)

        XCTAssertEqual(exception.id, 1)
        XCTAssertEqual(exception.processPath, "/usr/bin/test")
        XCTAssertEqual(exception.signerType, .signingId)
        XCTAssertNil(exception.teamId)
        XCTAssertEqual(exception.signingId, "com.apple.bluetoothd")
        XCTAssertEqual(exception.filePattern, "~/.ssh/*")
        XCTAssertTrue(exception.isGlob)
        XCTAssertNil(exception.expiresAt)
        XCTAssertEqual(exception.addedBy, "test")
    }

    func testDecode_allSignerTypes() throws {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        func makeJSON(signerType: String) -> String {
            """
            {
                "id": 1,
                "signer_type": "\(signerType)",
                "file_pattern": "test",
                "is_glob": false,
                "added_by": "test",
                "created_at": "2024-01-01T00:00:00Z"
            }
            """
        }

        let teamId = try decoder.decode(Exception.self, from: makeJSON(signerType: "team_id").data(using: .utf8)!)
        XCTAssertEqual(teamId.signerType, .teamId)

        let signingId = try decoder.decode(Exception.self, from: makeJSON(signerType: "signing_id").data(using: .utf8)!)
        XCTAssertEqual(signingId.signerType, .signingId)

        let adhoc = try decoder.decode(Exception.self, from: makeJSON(signerType: "adhoc").data(using: .utf8)!)
        XCTAssertEqual(adhoc.signerType, .adhoc)

        let unsigned = try decoder.decode(Exception.self, from: makeJSON(signerType: "unsigned").data(using: .utf8)!)
        XCTAssertEqual(unsigned.signerType, .unsigned)
    }

    func testDecode_withNullSignerType() throws {
        let json = """
        {
            "id": 1,
            "signer_type": null,
            "file_pattern": "test",
            "is_glob": false,
            "added_by": "test",
            "created_at": "2024-01-01T00:00:00Z"
        }
        """

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let exception = try decoder.decode(Exception.self, from: json.data(using: .utf8)!)

        XCTAssertNil(exception.signerType)
    }

    func testEncode_producesSnakeCaseKeys() throws {
        // Use non-nil values to ensure all keys are encoded
        // (Swift's Codable skips nil optional values)
        let exception = Exception(
            id: 1,
            processPath: "/test",
            signerType: .teamId,
            teamId: "TEAM",
            signingId: "com.test.app",
            filePattern: "test",
            isGlob: true,
            expiresAt: Date().addingTimeInterval(3600),
            addedBy: "test",
            comment: "test comment",
            createdAt: Date()
        )

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(exception)
        let jsonString = String(data: data, encoding: .utf8)!

        XCTAssertTrue(jsonString.contains("\"process_path\""))
        XCTAssertTrue(jsonString.contains("\"signer_type\""))
        XCTAssertTrue(jsonString.contains("\"team_id\""))
        XCTAssertTrue(jsonString.contains("\"signing_id\""))
        XCTAssertTrue(jsonString.contains("\"file_pattern\""))
        XCTAssertTrue(jsonString.contains("\"is_glob\""))
        XCTAssertTrue(jsonString.contains("\"expires_at\""))
        XCTAssertTrue(jsonString.contains("\"added_by\""))
        XCTAssertTrue(jsonString.contains("\"created_at\""))
    }
}

final class SignerTypeCodingTests: XCTestCase {

    func testEncode_producesSnakeCaseRawValue() throws {
        let encoder = JSONEncoder()

        let teamId = try encoder.encode(SignerType.teamId)
        XCTAssertEqual(String(data: teamId, encoding: .utf8), "\"team_id\"")

        let signingId = try encoder.encode(SignerType.signingId)
        XCTAssertEqual(String(data: signingId, encoding: .utf8), "\"signing_id\"")

        let adhoc = try encoder.encode(SignerType.adhoc)
        XCTAssertEqual(String(data: adhoc, encoding: .utf8), "\"adhoc\"")

        let unsigned = try encoder.encode(SignerType.unsigned)
        XCTAssertEqual(String(data: unsigned, encoding: .utf8), "\"unsigned\"")
    }

    func testDecode_fromSnakeCaseRawValue() throws {
        let decoder = JSONDecoder()

        XCTAssertEqual(try decoder.decode(SignerType.self, from: "\"team_id\"".data(using: .utf8)!), .teamId)
        XCTAssertEqual(try decoder.decode(SignerType.self, from: "\"signing_id\"".data(using: .utf8)!), .signingId)
        XCTAssertEqual(try decoder.decode(SignerType.self, from: "\"adhoc\"".data(using: .utf8)!), .adhoc)
        XCTAssertEqual(try decoder.decode(SignerType.self, from: "\"unsigned\"".data(using: .utf8)!), .unsigned)
    }
}

final class ViolationEventCodingTests: XCTestCase {

    func testDecode_fromAgentJSON() throws {
        let json = """
        {
            "id": "event-123",
            "timestamp": "2024-01-15T10:30:00Z",
            "rule_id": "ssh_keys",
            "file_path": "~/.ssh/id_rsa",
            "process_path": "/usr/bin/cat",
            "process_pid": 1234,
            "process_cmdline": "cat ~/.ssh/id_rsa",
            "process_euid": 501,
            "parent_pid": 1,
            "team_id": "APPLE123",
            "signing_id": "com.apple.cat",
            "action": "suspended",
            "process_tree": [
                {
                    "pid": 1234,
                    "ppid": 1,
                    "name": "cat",
                    "path": "/usr/bin/cat",
                    "cwd": "/Users/test",
                    "cmdline": "cat ~/.ssh/id_rsa",
                    "uid": 501,
                    "euid": 501,
                    "team_id": "APPLE123",
                    "signing_id": "com.apple.cat",
                    "is_platform_binary": true,
                    "is_stopped": true
                }
            ]
        }
        """

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let event = try decoder.decode(ViolationEvent.self, from: json.data(using: .utf8)!)

        XCTAssertEqual(event.id, "event-123")
        XCTAssertEqual(event.ruleId, "ssh_keys")
        XCTAssertEqual(event.filePath, "~/.ssh/id_rsa")
        XCTAssertEqual(event.processPath, "/usr/bin/cat")
        XCTAssertEqual(event.processPid, 1234)
        XCTAssertEqual(event.processCmdline, "cat ~/.ssh/id_rsa")
        XCTAssertEqual(event.processEuid, 501)
        XCTAssertEqual(event.parentPid, 1)
        XCTAssertEqual(event.teamId, "APPLE123")
        XCTAssertEqual(event.signingId, "com.apple.cat")
        XCTAssertEqual(event.action, "suspended")
        XCTAssertEqual(event.processTree.count, 1)

        let entry = event.processTree[0]
        XCTAssertEqual(entry.pid, 1234)
        XCTAssertEqual(entry.ppid, 1)
        XCTAssertEqual(entry.name, "cat")
        XCTAssertEqual(entry.path, "/usr/bin/cat")
        XCTAssertEqual(entry.cwd, "/Users/test")
        XCTAssertEqual(entry.cmdline, "cat ~/.ssh/id_rsa")
        XCTAssertEqual(entry.uid, 501)
        XCTAssertEqual(entry.euid, 501)
        XCTAssertEqual(entry.teamId, "APPLE123")
        XCTAssertEqual(entry.signingId, "com.apple.cat")
        XCTAssertTrue(entry.isPlatformBinary)
        XCTAssertTrue(entry.isStopped)
    }

    func testDecode_withMinimalFields() throws {
        let json = """
        {
            "id": "event-456",
            "timestamp": "2024-01-15T10:30:00Z",
            "file_path": "~/.ssh/id_rsa",
            "process_path": "/usr/bin/cat",
            "process_pid": 1234,
            "action": "blocked",
            "process_tree": [
                {
                    "pid": 1234,
                    "name": "cat",
                    "path": "/usr/bin/cat"
                }
            ]
        }
        """

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let event = try decoder.decode(ViolationEvent.self, from: json.data(using: .utf8)!)

        XCTAssertEqual(event.id, "event-456")
        XCTAssertNil(event.ruleId)
        XCTAssertNil(event.processCmdline)
        XCTAssertNil(event.processEuid)
        XCTAssertNil(event.parentPid)
        XCTAssertNil(event.teamId)
        XCTAssertNil(event.signingId)

        let entry = event.processTree[0]
        XCTAssertNil(entry.ppid)
        XCTAssertNil(entry.cwd)
        XCTAssertNil(entry.cmdline)
        XCTAssertNil(entry.uid)
        XCTAssertNil(entry.euid)
        XCTAssertNil(entry.teamId)
        XCTAssertNil(entry.signingId)
        XCTAssertFalse(entry.isPlatformBinary) // Default false
        XCTAssertFalse(entry.isStopped) // Default false
    }

    func testDecode_processTreeEntryDefaults() throws {
        // Test that missing boolean fields default to false
        let json = """
        {
            "pid": 1234,
            "name": "test",
            "path": "/test"
        }
        """

        let decoder = JSONDecoder()
        let entry = try decoder.decode(ProcessTreeEntry.self, from: json.data(using: .utf8)!)

        XCTAssertFalse(entry.isPlatformBinary)
        XCTAssertFalse(entry.isStopped)
    }
}

final class AddExceptionRequestCodingTests: XCTestCase {

    func testEncode_producesCorrectJSON() throws {
        let request = AddExceptionRequest(
            processPath: "/usr/bin/test",
            signerType: "team_id",
            teamId: "TEAM123",
            signingId: nil,
            filePattern: "~/.ssh/*",
            isGlob: true,
            expiresAt: nil,
            comment: "Test"
        )

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(request)
        let jsonString = String(data: data, encoding: .utf8)!

        // Check for snake_case keys (value assertions are format-sensitive)
        XCTAssertTrue(jsonString.contains("\"action\""))
        XCTAssertTrue(jsonString.contains("\"process_path\""))
        XCTAssertTrue(jsonString.contains("\"signer_type\""))
        XCTAssertTrue(jsonString.contains("\"team_id\""))
        XCTAssertTrue(jsonString.contains("\"file_pattern\""))
        XCTAssertTrue(jsonString.contains("\"is_glob\""))
        XCTAssertTrue(jsonString.contains("\"comment\""))

        // Verify values are present (accounting for potential slash escaping)
        XCTAssertTrue(jsonString.contains("add_exception"))
        // JSONEncoder may escape slashes as \/ or leave them unescaped
        XCTAssertTrue(jsonString.contains("usr") && jsonString.contains("bin") && jsonString.contains("test"))
        XCTAssertTrue(jsonString.contains("TEAM123"))
    }
}
