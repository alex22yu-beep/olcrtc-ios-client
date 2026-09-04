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

        let rt = MobileNew()

        do {
            try rt.setProvider(profile.carrier)
            try rt.setTransport(profile.transport)
            try rt.setRoom(profile.roomID)
            rt.setChannel(runtimeClientID ?? profile.clientID)
            try rt.setKey(profile.keyHex)
            try rt.setDNS("8.8.8.8:53")
            try rt.setSocksPort(Int32(socksPort))
            if !credentials.username.isEmpty || !credentials.password.isEmpty {
                try rt.setSocksCredentials(credentials.username, credentials.password)
            }
            try rt.setLivenessOptions(20_000, 15_000, 12)

            configureTransportOptions(rt, profile)

            try rt.start()
            try rt.waitReady(Int32(profile.startReadyTimeoutMilliseconds))
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
                Int32(profile.payloadInt("vp8-fps", default: 60)),
                Int32(profile.payloadInt("vp8-batch", default: 64))
            )
        case "seichannel":
            try? rt.setSEIOptions(
                Int32(profile.payloadInt("fps", default: 30)),
                Int32(profile.payloadInt("batch", default: 64)),
                Int32(profile.payloadInt("frag", default: 900)),
                Int32(profile.payloadInt("ack-ms", default: 2000))
            )
        case "videochannel":
            try? rt.setVideoOptions(
                Int32(profile.payloadInt("video-w", default: 1920)),
                Int32(profile.payloadInt("video-h", default: 1080)),
                Int32(profile.payloadInt("video-fps", default: 30)),
                Int32(profile.payloadInt("video-qr-size", default: 0)),
                profile.payload["video-qr-recovery"] ?? "low",
                profile.payload["video-codec"] ?? "qrcode",
                Int32(profile.payloadInt("video-tile-module", default: 4)),
                Int32(profile.payloadInt("video-tile-rs", default: 0))
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
            address.sin_port = UInt16(port).bigEndian
            address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

            let connectResult = withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
                    Darwin.connect(
                        descriptor,
                        socketAddress,
                        socklen_t(MemoryLayout<sockaddr_in>.size)
                    )
                }
            }

            guard connectResult == 0 else {
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
            address.sin_port = UInt16(port).bigEndian
            address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

            let connectResult = withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
                    Darwin.connect(
                        descriptor,
                        socketAddress,
                        socklen_t(MemoryLayout<sockaddr_in>.size)
                    )
                }
            }

            guard connectResult == 0 else {
                return false
            }

            // Auth
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

            // CONNECT request
            let targetIP = target.ip
            var connectRequest: [UInt8] = [0x05, 0x01, 0x00, 0x01]
            connectRequest.append(contentsOf: targetIP)
            connectRequest.append(UInt8((target.port >> 8) & 0xFF))
            connectRequest.append(UInt8(target.port & 0xFF))

            guard Self.writeAll(connectRequest, to: descriptor) else {
                return false
            }

            let response = Self.readExact(10, from: descriptor)
            return response != nil && response![1] == 0x00
        }.value
    }

    private enum SocksConnectTarget {
        case google

        var ip: [UInt8] {
            switch self {
            case .google:
                return [142, 250, 185, 206] // google.com
            }
        }

        var port: Int {
            443
        }
    }

    private static func setSocketTimeouts(_ descriptor: Int32) {
        var timeout = timeval(tv_sec: 5, tv_usec: 0)
        withUnsafePointer(to: &timeout) { pointer in
            _ = setsockopt(
                descriptor,
                SOL_SOCKET,
                SO_RCVTIMEO,
                pointer,
                socklen_t(MemoryLayout<timeval>.size)
            )
            _ = setsockopt(
                descriptor,
                SOL_SOCKET,
                SO_SNDTIMEO,
                pointer,
                socklen_t(MemoryLayout<timeval>.size)
            )
        }
    }

    private static func writeAll(_ bytes: [UInt8], to descriptor: Int32) -> Bool {
        var offset = 0
        while offset < bytes.count {
            let written = bytes.withUnsafeBytes { rawBuffer in
                Darwin.send(
                    descriptor,
                    rawBuffer.baseAddress!.advanced(by: offset),
                    bytes.count - offset,
                    0
                )
            }
            guard written > 0 else {
                return false
            }
            offset += written
        }
        return true
    }

    private static func readExact(_ count: Int, from descriptor: Int32) -> [UInt8]? {
        var bytes = [UInt8](repeating: 0, count: count)
        var offset = 0
        while offset < count {
            let received = bytes.withUnsafeMutableBytes { rawBuffer in
                Darwin.recv(
                    descriptor,
                    rawBuffer.baseAddress!.advanced(by: offset),
                    count - offset,
                    0
                )
            }
            guard received > 0 else {
                return nil
            }
            offset += received
        }
        return bytes
    }

    enum RuntimeError: LocalizedError {
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