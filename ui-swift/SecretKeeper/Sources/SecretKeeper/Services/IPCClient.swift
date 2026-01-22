import Foundation

protocol IPCClientDelegate: AnyObject {
    func ipcClient(_ client: IPCClient, didReceiveViolation violation: ViolationEvent)
    func ipcClient(_ client: IPCClient, didReceiveViolationHistory violations: [ViolationEvent])
    func ipcClient(_ client: IPCClient, didUpdateStatus status: AgentStatus)
    func ipcClient(_ client: IPCClient, didReceiveCategories categories: [ProtectedCategory])
    func ipcClient(_ client: IPCClient, didReceiveAgentInfo info: AgentInfo)
    func ipcClientDidConnect(_ client: IPCClient)
    func ipcClientDidDisconnect(_ client: IPCClient)
}

/// Agent binary info for auto-upgrade detection.
struct AgentInfo {
    /// Binary modification time (Unix timestamp in seconds).
    let binaryMtime: Int64
    /// Agent version string.
    let version: String
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

        // Copy socket path safely with bounds checking
        let maxPathLen = MemoryLayout.size(ofValue: addr.sun_path) - 1  // Reserve space for null terminator
        guard socketPath.utf8.count <= maxPathLen else {
            print("Socket path too long: \(socketPath.utf8.count) > \(maxPathLen)")
            close(socketHandle)
            return
        }

        socketPath.withCString { path in
            withUnsafeMutablePointer(to: &addr.sun_path) { sunPath in
                let ptr = UnsafeMutableRawPointer(sunPath).assumingMemoryBound(to: CChar.self)
                strncpy(ptr, path, maxPathLen)
                ptr[maxPathLen] = 0  // Ensure null termination
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

    /// Get all protected categories with their enabled status.
    func getCategories() {
        send(GetCategoriesRequest())
    }

    /// Enable or disable a protected category.
    func setCategoryEnabled(categoryId: String, enabled: Bool) {
        send(SetCategoryEnabledRequest(categoryId: categoryId, enabled: enabled))
    }

    /// Get agent binary info for auto-upgrade detection.
    func getAgentInfo() {
        send(GetAgentInfoRequest())
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
                // Violation event - ViolationEvent fields are flattened directly in the JSON
                if let eventData = try? JSONSerialization.data(withJSONObject: json) {
                    do {
                        let violation = try decoder.decode(ViolationEvent.self, from: eventData)
                        DispatchQueue.main.async { [weak self] in
                            guard let self = self else { return }
                            self.delegate?.ipcClient(self, didReceiveViolation: violation)
                        }
                    } catch {
                        fputs("[IPCClient] Failed to decode violation event: \(error)\n", stderr)
                        fputs("[IPCClient] Raw JSON: \(String(data: eventData, encoding: .utf8) ?? "nil")\n", stderr)
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

            case "categories":
                // Categories response
                if let categoriesArray = json["categories"] as? [[String: Any]] {
                    var categories: [ProtectedCategory] = []
                    for catDict in categoriesArray {
                        if let id = catDict["id"] as? String,
                           let enabled = catDict["enabled"] as? Bool,
                           let patterns = catDict["patterns"] as? [String] {
                            categories.append(ProtectedCategory(id: id, enabled: enabled, patterns: patterns))
                        }
                    }
                    DispatchQueue.main.async { [weak self] in
                        guard let self = self else { return }
                        self.delegate?.ipcClient(self, didReceiveCategories: categories)
                    }
                }

            case "agent_info":
                // Agent info response for auto-upgrade
                if let binaryMtime = json["binary_mtime"] as? Int64,
                   let version = json["version"] as? String {
                    let info = AgentInfo(binaryMtime: binaryMtime, version: version)
                    DispatchQueue.main.async { [weak self] in
                        guard let self = self else { return }
                        self.delegate?.ipcClient(self, didReceiveAgentInfo: info)
                    }
                }

            case "violations":
                // Violation history response
                if let eventsArray = json["events"] as? [[String: Any]] {
                    var violations: [ViolationEvent] = []
                    for eventDict in eventsArray {
                        if let eventData = try? JSONSerialization.data(withJSONObject: eventDict),
                           let violation = try? decoder.decode(ViolationEvent.self, from: eventData) {
                            violations.append(violation)
                        }
                    }
                    DispatchQueue.main.async { [weak self] in
                        guard let self = self else { return }
                        self.delegate?.ipcClient(self, didReceiveViolationHistory: violations)
                    }
                }

            case "success", "error", "pong", "exceptions", "config":
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

private struct GetCategoriesRequest: Codable {
    let action = "get_categories"
}

private struct SetCategoryEnabledRequest: Codable {
    let action = "set_category_enabled"
    let categoryId: String
    let enabled: Bool

    enum CodingKeys: String, CodingKey {
        case action
        case categoryId = "category_id"
        case enabled
    }
}

private struct GetAgentInfoRequest: Codable {
    let action = "get_agent_info"
}

