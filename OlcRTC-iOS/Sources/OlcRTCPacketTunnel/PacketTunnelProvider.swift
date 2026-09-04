import Foundation
import NetworkExtension

#if canImport(Mobile)
import Mobile
#endif

#if canImport(Tun2SocksKit)
import Tun2SocksKit
#endif

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private enum TunnelMode: String {
        case systemProxy
        case fullTunnel
        case splitTunnel

        var usesPacketEngine: Bool {
            self != .systemProxy
        }
    }

    private enum RoutingPreset: String {
        case allProxy
        case simpleRU
        case blockedOnly
        case localOnly

        var shouldBypassLocalRoutes: Bool {
            self != .allProxy
        }
    }

    private var socksPort = 18080
    private var tunnelStarted = false
    private var packetEngine: Tun2SocksPacketEngine?

    #if canImport(Mobile)
    private var runtime: MobileRuntime?
    #endif

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        guard let config = protocolConfiguration as? NETunnelProviderProtocol,
              let providerConfiguration = config.providerConfiguration,
              let carrier = providerConfiguration["carrier"] as? String,
              let transport = providerConfiguration["transport"] as? String,
              let roomID = providerConfiguration["roomID"] as? String,
              let keyHex = providerConfiguration["keyHex"] as? String,
              let clientID = providerConfiguration["clientID"] as? String else {
            completionHandler(TunnelError.invalidConfiguration)
            return
        }

        socksPort = providerConfiguration["socksPort"] as? Int ?? 18080
        let socksUser = providerConfiguration["socksUser"] as? String ?? ""
        let socksPass = providerConfiguration["socksPass"] as? String ?? ""
        let payload = providerConfiguration["payload"] as? [String: String] ?? [:]
        let tunnelMode = TunnelMode(rawValue: providerConfiguration["tunnelMode"] as? String ?? "") ?? .systemProxy
        let routingPreset = RoutingPreset(rawValue: providerConfiguration["routingPreset"] as? String ?? "") ?? .simpleRU

        #if canImport(Mobile)
        let rt = MobileNew()

        do {
            try rt.setProvider(carrier)
            try rt.setTransport(transport)
            try rt.setRoom(roomID)
            rt.setChannel(clientID)
            try rt.setKey(keyHex)
            try rt.setDNS("8.8.8.8:53")
            try rt.setSocksPort(Int32(socksPort))
            if !socksUser.isEmpty || !socksPass.isEmpty {
                try rt.setSocksCredentials(socksUser, socksPass)
            }
            try rt.setLivenessOptions(Int32(20_000), Int32(15_000), Int32(12))

            configureTransportOptions(rt, transport: transport, payload: payload)

            try rt.start()
            try rt.waitReady(Int32(readyTimeoutMilliseconds(carrier: carrier, transport: transport)))
        } catch {
            completionHandler(error)
            return
        }

        runtime = rt
        #else
        completionHandler(TunnelError.mobileFrameworkMissing)
        return
        #endif

        let settings = networkSettings(mode: tunnelMode, routingPreset: routingPreset, port: socksPort)
        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else {
                #if canImport(Mobile)
                try? rt.stop(5_000)
                #endif
                completionHandler(TunnelError.providerDeallocated)
                return
            }

            if let error {
                #if canImport(Mobile)
                try? rt.stop(5_000)
                self.runtime = nil
                #endif
                completionHandler(error)
                return
            }

            if tunnelMode.usesPacketEngine {
                do {
                    let engine = try Tun2SocksPacketEngine(
                        socksPort: self.socksPort,
                        socksUser: socksUser,
                        socksPass: socksPass
                    )
                    try engine.start()
                    self.packetEngine = engine
                } catch {
                    #if canImport(Mobile)
                    try? rt.stop(5_000)
                    self.runtime = nil
                    #endif
                    completionHandler(error)
                    return
                }
            }

            self.tunnelStarted = true
            completionHandler(nil)
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        packetEngine?.stop()
        packetEngine = nil

        #if canImport(Mobile)
        if tunnelStarted {
            try? runtime?.stop(5_000)
        }
        runtime = nil
        #endif
        tunnelStarted = false
        completionHandler()
    }

    private func networkSettings(mode: TunnelMode, routingPreset: RoutingPreset, port: Int) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.88.0.1")
        settings.mtu = 1280

        let ipv4 = NEIPv4Settings(addresses: ["10.88.0.2"], subnetMasks: ["255.255.255.0"])
        if mode.usesPacketEngine {
            ipv4.includedRoutes = [NEIPv4Route.default()]
            if mode == .splitTunnel || routingPreset.shouldBypassLocalRoutes {
                ipv4.excludedRoutes = Self.privateAndLocalRoutes()
            }
        }
        settings.ipv4Settings = ipv4
        settings.dnsSettings = NEDNSSettings(servers: ["8.8.8.8", "1.1.1.1"])

        if mode == .systemProxy {
            settings.proxySettings = proxySettings(port: port)
        }
        return settings
    }

    private static func privateAndLocalRoutes() -> [NEIPv4Route] {
        [
            route("10.0.0.0", "255.0.0.0"),
            route("100.64.0.0", "255.192.0.0"),
            route("127.0.0.0", "255.0.0.0"),
            route("169.254.0.0", "255.255.0.0"),
            route("172.16.0.0", "255.240.0.0"),
            route("192.168.0.0", "255.255.0.0"),
            route("224.0.0.0", "240.0.0.0")
        ]
    }

    private static func route(_ destination: String, _ mask: String) -> NEIPv4Route {
        NEIPv4Route(destinationAddress: destination, subnetMask: mask)
    }

    private func proxySettings(port: Int) -> NEProxySettings {
        let settings = NEProxySettings()
        settings.autoProxyConfigurationEnabled = true
        settings.proxyAutoConfigurationJavaScript = """
        function FindProxyForURL(url, host) {
            if (isPlainHostName(host)) { return "DIRECT"; }
            if (host === "localhost" || host === "127.0.0.1") { return "DIRECT"; }
            if (dnsDomainIs(host, ".local")) { return "DIRECT"; }
            return "SOCKS5 127.0.0.1:\(port); SOCKS 127.0.0.1:\(port); DIRECT";
        }
        """
        settings.excludeSimpleHostnames = true
        settings.exceptionList = [
            "*.local",
            "localhost",
            "127.0.0.1"
        ]
        return settings
    }

    private func readyTimeoutMilliseconds(carrier: String, transport: String) -> Int {
        if carrier.lowercased() == "jitsi", transport.lowercased() == "datachannel" {
            return 90_000
        }
        return 30_000
    }

    #if canImport(Mobile)
    private func configureTransportOptions(_ rt: MobileRuntime, transport: String, payload: [String: String]) {
        switch transport.lowercased() {
        case "vp8channel":
            try? rt.setVP8Options(
                Int32(payloadInt(payload, "vp8-fps", default: 60)),
                Int32(payloadInt(payload, "vp8-batch", default: 64))
            )
        case "seichannel":
            try? rt.setSEIOptions(
                Int32(payloadInt(payload, "fps", default: 30)),
                Int32(payloadInt(payload, "batch", default: 64)),
                Int32(payloadInt(payload, "frag", default: 1200)),
                Int32(payloadInt(payload, "ack-ms", default: 500))
            )
        case "videochannel":
            try? rt.setVideoOptions(
                Int32(payloadInt(payload, "video-w", default: 0)),
                Int32(payloadInt(payload, "video-h", default: 0)),
                Int32(payloadInt(payload, "video-fps", default: 0)),
                Int32(payloadInt(payload, "video-qr-size", default: 0)),
                payload["video-qr-recovery"] ?? "",
                payload["video-codec"] ?? "",
                Int32(payloadInt(payload, "video-tile-module", default: 0)),
                Int32(payloadInt(payload, "video-tile-rs", default: 0))
            )
        default:
            break
        }
    }
    #endif

    private func payloadInt(_ payload: [String: String], _ key: String, default defaultValue: Int) -> Int {
        Int(payload[key] ?? "") ?? defaultValue
    }
}

private final class Tun2SocksPacketEngine {
    private let config: String

    init(socksPort: Int, socksUser: String, socksPass: String) throws {
        #if canImport(Tun2SocksKit)
        config = Self.makeConfig(socksPort: socksPort, socksUser: socksUser, socksPass: socksPass)
        #else
        throw TunnelError.tun2socksUnavailable
        #endif
    }

    func start() throws {
        #if canImport(Tun2SocksKit)
        Socks5Tunnel.run(withConfig: .string(content: config)) { code in
            NSLog("Tun2SocksKit exited with code \(code)")
        }
        #else
        throw TunnelError.tun2socksUnavailable
        #endif
    }

    func stop() {
        #if canImport(Tun2SocksKit)
        Socks5Tunnel.quit()
        #endif
    }

    private static func makeConfig(socksPort: Int, socksUser: String, socksPass: String) -> String {
        var auth = ""
        if !socksUser.isEmpty || !socksPass.isEmpty {
            auth = """
              username: '\(escape(socksUser))'
              password: '\(escape(socksPass))'
            """
        }

        return """
        tunnel:
          mtu: 1280

        socks5:
          port: \(socksPort)
          address: '127.0.0.1'
          udp: 'udp'
        \(auth)

        misc:
          task-stack-size: 24576
          connect-timeout: 5000
          read-write-timeout: 60000
          log-file: stderr
          log-level: warn
        """
    }

    private static func escape(_ value: String) -> String {
        value.replacingOccurrences(of: "'", with: "''")
    }
}

private enum TunnelError: LocalizedError {
    case invalidConfiguration
    case providerDeallocated
    case mobileFrameworkMissing
    case olcrtcStartFailed
    case olcrtcReadyTimeout
    case tun2socksUnavailable

    var errorDescription: String? {
        switch self {
        case .invalidConfiguration:
            return "Packet tunnel provider configuration is invalid."
        case .providerDeallocated:
            return "OlcRTC VPN provider was deallocated."
        case .mobileFrameworkMissing:
            return "Mobile.xcframework is not linked to the packet tunnel."
        case .olcrtcStartFailed:
            return "olcRTC failed to start inside the packet tunnel."
        case .olcrtcReadyTimeout:
            return "olcRTC started but SOCKS was not ready before timeout."
        case .tun2socksUnavailable:
            return "Tun2SocksKit is not linked to the packet tunnel."
        }
    }
}