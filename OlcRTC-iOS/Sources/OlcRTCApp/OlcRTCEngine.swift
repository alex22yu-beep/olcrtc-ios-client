import Foundation
import Darwin

#if canImport(Mobile)
import Mobile
#endif

enum OlcRTCEngine {
    #if canImport(Mobile)
    static var runtime: MobileRuntime?
    #endif

    static func start(
        profile: OlcRTCProfile,
        socksPort: Int = 18080,
        credentials: SocksCredentials,
        runtimeClientID: String? = nil
    ) throws {
        #if canImport(Mobile)
        guard runtime == nil else {
            throw RuntimeError.alreadyRunning
        }

        guard let rt = MobileNew() else {
            throw RuntimeError.alreadyRunning
        }

        do {
            try rt.setProvider(profile.carrier)
            try rt.setTransport(profile.transport)
            try rt.setRoom(profile.roomID)
            rt.setChannel(runtimeClientID ?? profile.clientID)
            try rt.setKey(profile.keyHex)
            try rt.setDNS("8.8.8.8:53")
            try rt.setSocksPort(socksPort)
            if !credentials.username.isEmpty || !credentials.password.isEmpty {
                try rt.setSocksCredentials(credentials.username, password: credentials.password)
            }
            try rt.setLivenessOptions(20_000, timeoutMillis: 15_000, failures: 12)

            configureTransportOptions(rt, profile)

            try rt.start()
            try rt.waitReady(profile.startReadyTimeoutMilliseconds)
        } catch {
            try? rt.stop(5_000)
            throw error
        }

        runtime = rt
        #else
        throw RuntimeError.frameworkMissing
        #endif
    }

    static func stop() {
        #if canImport(Mobile)
        try? runtime?.stop(5_000)
        runtime = nil
        #endif
    }

    #if canImport(Mobile)
    private static func configureTransportOptions(_ rt: MobileRuntime, _ profile: OlcRTCProfile) {
        switch profile.transport {
        case "vp8channel":
            try? rt.setVP8Options(
                profile.payloadInt("vp8-fps", default: 60),
                batchSize: profile.payloadInt("vp8-batch", default: 64)
            )
        case "seichannel":
            try? rt.setSEIOptions(
                profile.payloadInt("fps", default: 30),
                batchSize: profile.payloadInt("batch", default: 64),
                fragmentSize: profile.payloadInt("frag", default: 1200),
                ackTimeoutMillis: profile.payloadInt("ack-ms", default: 500)
            )
        case "videochannel":
            try? rt.setVideoOptions(
                profile.payloadInt("video-w", default: 0),
                height: profile.payloadInt("video-h", default: 0),
                fps: profile.payloadInt("video-fps", default: 0),
                qrSize: profile.payloadInt("video-qr-size", default: 0),
                qrRecovery: profile.payload["video-qr-recovery"] ?? "",
                codec: profile.payload["video-codec"] ?? "",
                tileModule: profile.payloadInt("video-tile-module", default: 0),
                tileRS: profile.payloadInt("video-tile-rs", default: 0)
            )
        default:
            break
        }
    }
    #endif

    static func checkLocalSocks(port: Int, credentials: SocksCredentials, timeoutNanoseconds: UInt64 = 5_000_000_000) async -> Bool {
        await withTaskGroup(of: Bool.self) { group in
            group.addTask {
                await Self.socksAuthHandshake(port: port, credentials: credentials)
            }
            group.addTask {
                try? await Task.sleep(nanoseconds: timeoutNanoseconds)
                return false
            }

            for await result in group {
                if result {
                    group.cancelAll()
                    return true
                }
            }

            return false
        }
    }

    static func checkTunnelConnectivity(port: Int, credentials: SocksCredentials, timeoutNanoseconds: UInt64 = 12_000_000_000) async -> Bool {
        await checkTunnelConnectivity(
            port: port,
            credentials: credentials,
            targets: SocksConnectTarget.defaults,
            timeoutNanoseconds: timeoutNanoseconds
        )
    }

    static func checkGoogleConnectivity(port: Int, credentials: SocksCredentials, timeoutNanoseconds: UInt64 = 12_000_000_000) async -> Bool {
        await checkTunnelConnectivity(
            port: port,
            credentials: credentials,
            targets: [.google],
            timeoutNanoseconds: timeoutNanoseconds
        )
    }

    private static func checkTunnelConnectivity(
        port: Int,
        credentials: SocksCredentials,
        targets: [SocksConnectTarget],
        timeoutNanoseconds: UInt64
    ) async -> Bool {
        await withTaskGroup(of: Bool.self) { group in
            group.addTask {
                try? await Task.sleep(nanoseconds: timeoutNanoseconds)
                return false
            }

            for target in targets {
                group.addTask {
                    await Self.socksConnectProbe(port: port, credentials: credentials, target: target)
                }
            }

            for await result in group {
                if result {
                    group.cancelAll()
                    return true
                }
            }

            return false
        }
    }

    private static func socksAuthHandshake(port: Int, credentials: SocksCredentials) async -> Bool {
        await Task.detached(priority: .utility) {
            let username = Array(credentials.username.utf8)
            let password = Array(credentials.password.utf8)
            guard (1...65_535).contains(port),
                  username.count <= 255,
                  password.count <= 255 else {
                return false
            }

            let descriptor = socket(AF_INET, SOCK_STREAM, 0)
            guard descriptor >= 0 else {
                return false
            }
            defer {
                close(descriptor)
            }
            Self.setSocketTimeouts(descriptor)

            var address = sockaddr_in()
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            address.sin_family = sa_family_t(AF_INET)
            address.sin_port = in_port_t(port).bigEndian
            address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

            let result = withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
                    Darwin.connect(
                        descriptor,
                        socketAddress,
                        socklen_t(MemoryLayout<sockaddr_in>.size)
                    )
                }
            }

            guard result == 0 else {
                return false
            }

            guard Self.writeAll([0x05, 0x01, 0x02], to: descriptor),
                  Self.readExact(2, from: descriptor) == [0x05, 0x02] else {
                return false
            }

            var authRequest: [UInt8] = [0x01, UInt8(username.count)]
            authRequest.append(contentsOf: username)
            authRequest.append(UInt8(password.count))
            authRequest.append(contentsOf: password)

            return Self.writeAll(authRequest, to: descriptor)
                && Self.readExact(2, from: descriptor) == [0x01, 0x00]
        }.value
    }

    private static func socksConnectProbe(port: Int, credentials: SocksCredentials, target: SocksConnectTarget) async -> Bool {
        await Task.detached(priority: .utility) {
            let username = Array(credentials.username.utf8)
            let password = Array(credentials.password.utf8)
            guard (1...65_535).contains(port),
                  username.count <= 255,
                  password.count <= 255 else {
                return false
            }

            let descriptor = socket(AF_INET, SOCK_STREAM, 0)
            guard descriptor >= 0 else {
                return false
            }
            defer {
                close(descriptor)
            }
            Self.setSocketTimeouts(descriptor)

            var address = sockaddr_in()
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            address.sin_family = sa_family_t(AF_INET)
            address.sin_port = in_port_t(port).bigEndian
            address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

            let result = withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
                    Darwin.connect(
                        descriptor,
                        socketAddress,
                        socklen_t(MemoryLayout<sockaddr_in>.size)
                    )
                }
            }

            guard result == 0 else {
                return false
            }

            guard Self.writeAll([0x05, 0x01, 0x02], to: descriptor),
                  Self.readExact(2, from: descriptor) == [0x05, 0x02] else {
                return false
            }

            var authRequest: [UInt8] = [0x01, UInt8(username.count)]
            authRequest.append(contentsOf: username)
            authRequest.append(UInt8(password.count))
            authRequest.append(contentsOf: password)

            guard Self.writeAll(authRequest, to: descriptor),
                  Self.readExact(2, from: descriptor) == [0x01, 0x00] else {
                return false
            }

            var connectRequest: [UInt8] = [0x05, 0x01, 0x00]
            switch target.address {
            case .ipv4(let ip):
                var parts: [UInt8] = []
                for octet in ip.split(separator: ".") {
                    parts.append(UInt8(octet) ?? 0)
                }
                connectRequest.append(contentsOf: [0x01, 0x04] + parts)
            case .domain(let domain):
                let domainBytes = Array(domain.utf8)
                connectRequest.append(contentsOf: [0x01, 0x03, UInt8(domainBytes.count)] + domainBytes)
            }
            connectRequest.append(contentsOf: withUnsafeBytes(of: target.port.bigEndian) { Array($0) })

            guard Self.writeAll(connectRequest, to: descriptor) else {
                return false
            }

            let response = Self.readExact(4, from: descriptor)
            return response.count >= 2 && response[0] == 0x05 && response[1] == 0x00
        }.value
    }

    private static func setSocketTimeouts(_ descriptor: Int32) {
        var timeout = timeval(tv_sec: 5, tv_usec: 0)
        setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    }

    private static func writeAll(_ bytes: [UInt8], to descriptor: Int32) -> Bool {
        var written = 0
        while written < bytes.count {
            let result = bytes.withUnsafeBytes { buffer in
                send(descriptor, buffer.baseAddress!.advanced(by: written), bytes.count - written, 0)
            }
            guard result > 0 else {
                return false
            }
            written += result
        }
        return true
    }

    private static func readExact(_ count: Int, from descriptor: Int32) -> [UInt8] {
        var buffer = [UInt8](repeating: 0, count: count)
        var received = 0
        while received < count {
            let result = recv(descriptor, &buffer[received], count - received, 0)
            guard result > 0 else {
                return []
            }
            received += result
        }
        return buffer
    }

    private enum RuntimeError: LocalizedError {
        case frameworkMissing
        case alreadyRunning

        var errorDescription: String? {
            switch self {
            case .frameworkMissing:
                return "Mobile.xcframework is not linked. Build it with Scripts/build-mobile-xcframework.sh."
            case .alreadyRunning:
                return "olcRTC is already running."
            }
        }
    }
}

private struct SocksConnectTarget: Sendable {
    enum Address: Sendable {
        case ipv4(String)
        case domain(String)
    }

    let address: Address
    let port: UInt16

    static let google = SocksConnectTarget(address: .domain("www.google.com"), port: 443)

    static let defaults: [SocksConnectTarget] = [
        SocksConnectTarget(address: .ipv4("1.1.1.1"), port: 443),
        SocksConnectTarget(address: .ipv4("8.8.8.8"), port: 443),
        SocksConnectTarget(address: .domain("www.apple.com"), port: 443)
    ]
}