import Foundation

protocol IPCClientDelegate: AnyObject {
    func ipcClient(_ client: IPCClient, didReceiveViolation violation: ViolationEvent)
    func ipcClient(_ client: IPCClient, didUpdateStatus status: AgentStatus)
    func ipcClientDidConnect(_ client: IPCClient)
    func ipcClientDidDisconnect(_ client: IPCClient)
}

/// Client for communicating with the SecretKeeper agent via Unix socket.
class IPCClient: NSObject {
    private let socketPath: String
    private var inputStream: InputStream?
    private var outputStream: OutputStream?
    private var isConnected = false
    private let queue = DispatchQueue(label: "com.codegroove.secretkeeper.ipc", qos: .userInitiated)
    private var readBuffer = Data()

    weak var delegate: IPCClientDelegate?

    private let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()

    private let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }()

    init(socketPath: String) {
        self.socketPath = socketPath
    }

    /// Connect to the agent socket.
    func connect() {
        queue.async { [weak self] in
            self?.doConnect()
        }
    }

    private func doConnect() {
        guard !isConnected else { return }

        // Create Unix domain socket streams
        var readStream: Unmanaged<CFReadStream>?
        var writeStream: Unmanaged<CFWriteStream>?

        CFStreamCreatePairWithSocketToHost(
            kCFAllocatorDefault,
            nil,
            0,
            &readStream,
            &writeStream
        )

        // For Unix sockets, we need to use a different approach
        let socketHandle = socket(AF_UNIX, SOCK_STREAM, 0)
        guard socketHandle >= 0 else {
            print("Failed to create socket")
            return
        }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)

        // Copy socket path
        socketPath.withCString { path in
            withUnsafeMutablePointer(to: &addr.sun_path) { sunPath in
                let ptr = UnsafeMutableRawPointer(sunPath).assumingMemoryBound(to: CChar.self)
                strcpy(ptr, path)
            }
        }

        let connectResult = withUnsafePointer(to: &addr) { addrPtr in
            addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                Darwin.connect(socketHandle, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }

        guard connectResult == 0 else {
            print("Failed to connect to \(socketPath): \(String(cString: strerror(errno)))")
            close(socketHandle)
            return
        }

        // Create streams from socket
        CFStreamCreatePairWithSocket(
            kCFAllocatorDefault,
            Int32(socketHandle),
            &readStream,
            &writeStream
        )

        guard let input = readStream?.takeRetainedValue(),
              let output = writeStream?.takeRetainedValue() else {
            print("Failed to create streams")
            close(socketHandle)
            return
        }

        inputStream = input as InputStream
        outputStream = output as OutputStream

        CFReadStreamSetProperty(input, CFStreamPropertyKey(rawValue: kCFStreamPropertyShouldCloseNativeSocket), kCFBooleanTrue)
        CFWriteStreamSetProperty(output, CFStreamPropertyKey(rawValue: kCFStreamPropertyShouldCloseNativeSocket), kCFBooleanTrue)

        inputStream?.delegate = self
        outputStream?.delegate = self

        inputStream?.schedule(in: .main, forMode: .common)
        outputStream?.schedule(in: .main, forMode: .common)

        inputStream?.open()
        outputStream?.open()

        isConnected = true

        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.delegate?.ipcClientDidConnect(self)
        }

        // Start reading
        startReading()
    }

    /// Disconnect from the agent.
    func disconnect() {
        queue.async { [weak self] in
            self?.doDisconnect()
        }
    }

    private func doDisconnect() {
        inputStream?.close()
        outputStream?.close()
        inputStream = nil
        outputStream = nil
        isConnected = false

        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.delegate?.ipcClientDidDisconnect(self)
        }
    }

    /// Subscribe to real-time events.
    func subscribe(filter: EventFilter? = nil) {
        let request = SubscribeRequest(filter: filter)
        send(request)
    }

    /// Get agent status.
    func getStatus() {
        send(StatusRequest())
    }

    /// Get current mode.
    func getMode() {
        send(GetModeRequest())
    }

    /// Set enforcement mode.
    func setMode(_ mode: EnforcementMode) {
        send(SetModeRequest(mode: mode.rawValue))
    }

    /// Allow a suspended process to continue (one-time).
    func allowOnce(eventId: String) {
        send(AllowOnceRequest(eventId: eventId))
    }

    /// Add permanent/temporary exception for a violation.
    func allowPermanently(eventId: String, expiresAt: Date? = nil, comment: String? = nil) {
        send(AllowPermanentlyRequest(eventId: eventId, expiresAt: expiresAt, comment: comment))
    }

    /// Kill a suspended process.
    func killProcess(eventId: String) {
        send(KillRequest(eventId: eventId))
    }

    /// Get violation history.
    func getViolations(limit: Int? = nil, since: Date? = nil) {
        send(GetViolationsRequest(limit: limit, since: since))
    }

    /// Get all active exceptions.
    func getExceptions() {
        send(GetExceptionsRequest())
    }

    /// Add a new exception.
    func addException(
        processPath: String? = nil,
        codeSigner: String? = nil,
        filePattern: String,
        isGlob: Bool = true,
        expiresAt: Date? = nil,
        comment: String? = nil
    ) {
        send(AddExceptionRequest(
            processPath: processPath,
            codeSigner: codeSigner,
            filePattern: filePattern,
            isGlob: isGlob,
            expiresAt: expiresAt,
            comment: comment
        ))
    }

    /// Remove an exception by ID.
    func removeException(id: Int64) {
        send(RemoveExceptionRequest(id: id))
    }

    /// Ping the agent.
    func ping() {
        send(PingRequest())
    }

    // MARK: - Private

    private func send<T: Encodable>(_ request: T) {
        queue.async { [weak self] in
            self?.doSend(request)
        }
    }

    private func doSend<T: Encodable>(_ request: T) {
        guard isConnected, let output = outputStream else {
            print("Not connected")
            return
        }

        do {
            var data = try encoder.encode(request)
            data.append(contentsOf: [0x0A]) // Newline

            let bytes = [UInt8](data)
            let written = output.write(bytes, maxLength: bytes.count)

            if written < 0 {
                print("Write error: \(output.streamError?.localizedDescription ?? "unknown")")
            }
        } catch {
            print("Encode error: \(error)")
        }
    }

    private func startReading() {
        queue.async { [weak self] in
            self?.readLoop()
        }
    }

    private func readLoop() {
        guard isConnected, let input = inputStream else { return }

        var buffer = [UInt8](repeating: 0, count: 4096)

        while input.hasBytesAvailable {
            let bytesRead = input.read(&buffer, maxLength: buffer.count)

            if bytesRead > 0 {
                readBuffer.append(contentsOf: buffer[0..<bytesRead])
                processBuffer()
            } else if bytesRead < 0 {
                print("Read error: \(input.streamError?.localizedDescription ?? "unknown")")
                doDisconnect()
                return
            }
        }

        // Continue reading
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) { [weak self] in
            self?.queue.async {
                self?.readLoop()
            }
        }
    }

    private func processBuffer() {
        // Look for newline-delimited JSON messages
        while let newlineIndex = readBuffer.firstIndex(of: 0x0A) {
            let lineData = readBuffer[..<newlineIndex]
            readBuffer = Data(readBuffer[(newlineIndex + 1)...])

            if lineData.isEmpty { continue }

            handleMessage(Data(lineData))
        }
    }

    private func handleMessage(_ data: Data) {
        // Try to determine message type
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            print("Failed to parse JSON")
            return
        }

        if let status = json["status"] as? String {
            switch status {
            case "event":
                // Violation event
                if let eventData = try? JSONSerialization.data(withJSONObject: json),
                   let response = try? decoder.decode(EventResponse.self, from: eventData) {
                    DispatchQueue.main.async { [weak self] in
                        guard let self = self else { return }
                        self.delegate?.ipcClient(self, didReceiveViolation: response.event)
                    }
                }

            case "status":
                // Agent status
                if let statusData = try? JSONSerialization.data(withJSONObject: json),
                   let agentStatus = try? decoder.decode(AgentStatus.self, from: statusData) {
                    DispatchQueue.main.async { [weak self] in
                        guard let self = self else { return }
                        self.delegate?.ipcClient(self, didUpdateStatus: agentStatus)
                    }
                }

            case "success", "error", "pong", "violations", "exceptions", "config":
                // Handle other response types as needed
                break

            default:
                break
            }
        }
    }
}

extension IPCClient: StreamDelegate {
    func stream(_ aStream: Stream, handle eventCode: Stream.Event) {
        switch eventCode {
        case .errorOccurred:
            print("Stream error: \(aStream.streamError?.localizedDescription ?? "unknown")")
            doDisconnect()
        case .endEncountered:
            print("Stream ended")
            doDisconnect()
        default:
            break
        }
    }
}

// MARK: - Request Types

private struct SubscribeRequest: Codable {
    let action = "subscribe"
    let filter: EventFilter?
}

struct EventFilter: Codable {
    let filePatterns: [String]?
    let ruleIds: [String]?
    let deniedOnly: Bool?

    enum CodingKeys: String, CodingKey {
        case filePatterns = "file_patterns"
        case ruleIds = "rule_ids"
        case deniedOnly = "denied_only"
    }
}

private struct StatusRequest: Codable {
    let action = "status"
}

private struct GetModeRequest: Codable {
    let action = "get_mode"
}

private struct SetModeRequest: Codable {
    let action = "set_mode"
    let mode: String
}

private struct AllowOnceRequest: Codable {
    let action = "allow_once"
    let eventId: String

    enum CodingKeys: String, CodingKey {
        case action
        case eventId = "event_id"
    }
}

private struct AllowPermanentlyRequest: Codable {
    let action = "allow_permanently"
    let eventId: String
    let expiresAt: Date?
    let comment: String?

    enum CodingKeys: String, CodingKey {
        case action
        case eventId = "event_id"
        case expiresAt = "expires_at"
        case comment
    }
}

private struct KillRequest: Codable {
    let action = "kill"
    let eventId: String

    enum CodingKeys: String, CodingKey {
        case action
        case eventId = "event_id"
    }
}

private struct GetViolationsRequest: Codable {
    let action = "get_violations"
    let limit: Int?
    let since: Date?
}

private struct GetExceptionsRequest: Codable {
    let action = "get_exceptions"
}

private struct RemoveExceptionRequest: Codable {
    let action = "remove_exception"
    let id: Int64
}

private struct PingRequest: Codable {
    let action = "ping"
}

// MARK: - Response Types

private struct EventResponse: Codable {
    let status: String
    let event: ViolationEvent

    enum CodingKeys: String, CodingKey {
        case status
        case event
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let dict = try container.decode([String: AnyCodable].self)

        status = dict["status"]?.value as? String ?? "event"

        // The event data is in the response itself (minus the status field)
        var eventDict = dict
        eventDict.removeValue(forKey: "status")

        let eventData = try JSONSerialization.data(withJSONObject: eventDict.mapValues { $0.value })
        let eventDecoder = JSONDecoder()
        eventDecoder.dateDecodingStrategy = .iso8601
        event = try eventDecoder.decode(ViolationEvent.self, from: eventData)
    }
}

// Helper for decoding arbitrary JSON
struct AnyCodable: Codable {
    let value: Any

    init(_ value: Any) {
        self.value = value
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()

        if let bool = try? container.decode(Bool.self) {
            value = bool
        } else if let int = try? container.decode(Int.self) {
            value = int
        } else if let double = try? container.decode(Double.self) {
            value = double
        } else if let string = try? container.decode(String.self) {
            value = string
        } else if let array = try? container.decode([AnyCodable].self) {
            value = array.map { $0.value }
        } else if let dict = try? container.decode([String: AnyCodable].self) {
            value = dict.mapValues { $0.value }
        } else {
            value = NSNull()
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()

        switch value {
        case let bool as Bool:
            try container.encode(bool)
        case let int as Int:
            try container.encode(int)
        case let double as Double:
            try container.encode(double)
        case let string as String:
            try container.encode(string)
        case let array as [Any]:
            try container.encode(array.map { AnyCodable($0) })
        case let dict as [String: Any]:
            try container.encode(dict.mapValues { AnyCodable($0) })
        default:
            try container.encodeNil()
        }
    }
}
