import SwiftUI
import AppKit
import UniformTypeIdentifiers

struct TargetStatus { var result: ProbeResult?; var running = false }

@MainActor final class Checker: ObservableObject {
    @Published var section = 0
    // Files
    @Published var files: [URL] = []
    @Published var hostname = ""
    @Published var purpose: Purpose = .tlsServer
    @Published var platform: Platform = .generic
    @Published var password = ""
    @Published var report: FileReport?
    // WireGuard
    @Published var wgFiles: [URL] = []
    @Published var wgPlatform: Platform = .pfSense
    @Published var wgExpected = ""
    @Published var wgFindings: [Finding]?
    @Published var wgSummary = ""
    func checkWireGuard() {
        let urls = wgFiles, exp = wgExpected
        Task {
            let r = await Task.detached { WGCheck.inspect(urls, expectedPublicKey: exp) }.value
            wgFindings = r.findings
            wgSummary = r.configs.map { "\($0.name) (\($0.source)): \($0.peers.count) peer\($0.peers.count == 1 ? "" : "s")\($0.derivedPublicKey.map { ", public key \($0)" } ?? "")" }.joined(separator: "\n")
        }
    }
    // IKEv2 IPsec
    @Published var ipFiles: [URL] = []
    @Published var ipPlatform: Platform = .pfSense
    @Published var ipIdentifier = ""
    @Published var ipFindings: [Finding]?
    @Published var ipChain: [Certificate] = []
    func checkIPsec() {
        let urls = ipFiles, id = ipIdentifier
        Task {
            let r = await Task.detached { IPsecCheck.inspect(urls, expectedIdentifier: id) }.value
            ipFindings = r.findings; ipChain = (r.servers + r.cas).map(\.cert)
        }
    }
    // RADIUS
    @Published var radFiles: [URL] = []
    @Published var radName = ""
    @Published var radPlatform: Platform = .windowsAD
    @Published var radFindings: [Finding]?
    @Published var radChain: [Certificate] = []
    @Published var radHost = ""
    @Published var radPort = "1812"
    @Published var radMethod: EAPMethod = .peap
    @Published var radSecret = ""
    @Published var radRunning = false
    @Published var radTranscript: [String] = []
    func checkRadiusFiles() {
        let urls = radFiles, name = radName
        Task {
            let r = await Task.detached { RadiusCheck.inspect(urls, expectedName: name) }.value
            radFindings = r.findings; radChain = r.chain; radTranscript = []
        }
    }
    func probeRadius() {
        let host = radHost.trimmingCharacters(in: .whitespaces), port = Int(radPort) ?? -1, method = radMethod, name = radName
        let secret = radSecret; radSecret = ""   // cleared from the UI immediately; never stored
        radRunning = true
        Task {
            let r = await Task.detached { RadiusProbe.run(host: host, port: port, method: method, expectedName: name, secret: secret) }.value
            radFindings = r.findings; radChain = r.chain; radTranscript = r.transcript; radRunning = false
        }
    }
    // Remote access (RDP, RD Gateway, WinRM)
    @Published var rem = RemoteForm()
    @Published var remRunning = false
    @Published var remResult: ProbeResult?
    @Published var remTarget: Target?
    func probeRemote() {
        let t = rem.target, http = rem.runsHTTPCheck
        remRunning = true; remTarget = t; remResult = nil   // never show the previous host's result for the new target
        Task {
            var r = await Probe.run(t)
            if http {
                let h = await WinRMHTTP.check(host: t.host)
                r.transcript += h.transcript
                r.findings = (r.findings + h.findings).sorted { $0.severity == $1.severity ? $0.id < $1.id : $0.severity > $1.severity }
            }
            remResult = r; remRunning = false
        }
    }
    func addRemoteTarget() { var t = rem.target; t.name = "\(rem.service.rawValue) \(t.host)"; if commit(t) { section = 1 } }
    // Targets
    @Published var targets: [Target] = []
    @Published var status: [UUID: TargetStatus] = [:]
    @Published var selected: UUID?
    @Published var editing: Target?
    @Published var message: String?
    let store = TargetStore()
    static var pfxSupported: Bool { if #available(macOS 15.0, *) { return true } else { return false } }

    init() { do { targets = try store.load() } catch { message = "Saved targets could not be read: \(error.localizedDescription)" } }

    func chooseFiles() {
        let panel = NSOpenPanel(); panel.allowsMultipleSelection = true; panel.canChooseDirectories = false
        panel.message = "Choose certificates, chains, CSRs, keys or PFX files. Files are read in memory only and never copied."
        guard panel.runModal() == .OK else { return }
        files = panel.urls; report = nil
    }
    func checkFiles() {
        let urls = files, host = hostname, purpose = purpose
        let pw = password.isEmpty ? nil : password
        password = "" // the password is not retained after the check starts
        Task {
            let r = await Task.detached { FileCheck.inspect(urls, hostname: host, purpose: purpose, password: pw) }.value
            report = r
        }
    }
    func save() { do { try store.save(targets) } catch { message = error.localizedDescription } }
    @discardableResult func commit(_ t: Target) -> Bool {
        do {
            try t.validate()
            if let i = targets.firstIndex(where: { $0.id == t.id }) { targets[i] = t } else { targets.append(t) }
            editing = nil; selected = t.id; save(); return true
        } catch { message = error.localizedDescription; return false }
    }
    func delete(_ t: Target) { targets.removeAll { $0.id == t.id }; status[t.id] = nil; if selected == t.id { selected = nil }; save() }
    func check(_ t: Target) {
        status[t.id, default: TargetStatus()].running = true
        Task { let r = await Probe.run(t); status[t.id] = TargetStatus(result: r, running: false) }
    }
    func checkAll() {
        let list = targets
        for t in list { status[t.id, default: TargetStatus()].running = true }
        Task {
            await withTaskGroup(of: (UUID, ProbeResult).self) { group in
                var iterator = list.makeIterator(); var active = 0
                func next() { if let t = iterator.next() { active += 1; group.addTask { (t.id, await Probe.run(t)) } } }
                for _ in 0..<4 { next() }
                while let (id, r) = await group.next() { status[id] = TargetStatus(result: r, running: false); active -= 1; next() }
            }
        }
    }
    var anyRunning: Bool { status.values.contains { $0.running } }
}

@main struct CertificateCheckerApp: App {
    @StateObject private var model = Checker()
    var body: some Scene {
        WindowGroup("Certificate Checker") { ContentView().environmentObject(model) }
            .defaultSize(width: 1180, height: 820)
            .commands { CommandGroup(replacing: .newItem) {} }
    }
}

let accent = Color(red: 0.07, green: 0.33, blue: 0.62)

struct ContentView: View {
    @EnvironmentObject var m: Checker
    var body: some View {
        HStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 18) {
                Image(systemName: "checkmark.seal").font(.system(size: 34)).foregroundStyle(accent)
                Text("CERTIFICATE\nCHECKER").font(.system(size: 15, weight: .bold, design: .rounded)).tracking(2)
                Text("Evidence before renewal.").font(.callout).foregroundStyle(.secondary)
                Divider()
                rail(0, "doc.badge.ellipsis", "Files", "PEM, DER, PFX, CSR, keys")
                rail(1, "network.badge.shield.half.filled", "Targets", "HTTPS, LDAPS, mail, MySQL, RDP")
                rail(2, "lock.rotation", "WireGuard", "wg-quick .conf, pfSense XML")
                rail(3, "lock.shield", "IKEv2 IPsec", "pfSense Cert Manager, config.xml")
                rail(4, "wifi.router", "RADIUS", "EAP server certificate, eapol_test")
                rail(5, "display", "Remote access", "RDP, RD Gateway, WinRM")
                Spacer()
                Label("On demand only", systemImage: "hand.tap").font(.caption)
                Text("Nothing runs in the background. Private keys are read in memory only and never logged, cached, copied or uploaded. Fix commands are copy-only.").font(.caption).foregroundStyle(.secondary)
                Text("macOS 14+ · v0.5.2\(AppConfig.current.organizationName.isEmpty ? "" : " · " + AppConfig.current.organizationName)").font(.caption2).foregroundStyle(.secondary)
                Text("Config: \(AppConfig.source == "built-in defaults" ? "built-in defaults" : (AppConfig.source as NSString).abbreviatingWithTildeInPath)\(AppConfig.loadError == nil ? "" : " (error, defaults used)")").font(.caption2).foregroundStyle(.secondary).lineLimit(2).help(AppConfig.loadError ?? AppConfig.source).textSelection(.enabled)
            }.padding(24).frame(width: 230).frame(maxHeight: .infinity).background(accent.opacity(0.055))
            Divider()
            Group { if m.section == 0 { FilesView() } else if m.section == 1 { TargetsView() } else if m.section == 2 { WireGuardView() } else if m.section == 3 { IPsecView() } else if m.section == 4 { RadiusView() } else { RemoteView() } }.frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .alert("Certificate Checker", isPresented: Binding(get: { m.message != nil }, set: { if !$0 { m.message = nil } })) { Button("OK") {} } message: { Text(m.message ?? "") }
        .sheet(item: $m.editing) { t in TargetEditor(target: t) }
        .onDisappear { m.password = ""; m.radSecret = "" }
        .onReceive(NotificationCenter.default.publisher(for: NSWindow.willCloseNotification)) { _ in m.password = ""; m.radSecret = "" }
    }
    func rail(_ i: Int, _ icon: String, _ title: String, _ sub: String) -> some View {
        Button { m.section = i } label: {
            HStack(spacing: 10) {
                Image(systemName: icon).frame(width: 22)
                VStack(alignment: .leading) { Text(title).fontWeight(.semibold); Text(sub).font(.caption).foregroundStyle(.secondary) }
                Spacer()
            }.padding(8).background(m.section == i ? accent.opacity(0.15) : .clear, in: RoundedRectangle(cornerRadius: 8))
        }.buttonStyle(.plain)
    }
}

struct FilesView: View {
    @EnvironmentObject var m: Checker
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("Check certificate files.").font(.system(size: 30, weight: .semibold, design: .rounded))
                Text("Verify chain order, intermediates, SAN, EKU, expiry, weak algorithms and key pairing without contacting any server.").foregroundStyle(.secondary)
                GroupBox {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack {
                            Button("Choose files…") { m.chooseFiles() }
                            Text(m.files.isEmpty ? "No files selected" : m.files.map(\.lastPathComponent).joined(separator: ", ")).foregroundStyle(.secondary).lineLimit(2)
                        }
                        .onDrop(of: [.fileURL], isTargeted: nil) { providers in
                            for p in providers { _ = p.loadObject(ofClass: URL.self) { url, _ in if let url { Task { @MainActor in m.files.append(url); m.report = nil } } } }
                            return true
                        }
                        HStack {
                            TextField("Expected hostname (optional)", text: $m.hostname).frame(maxWidth: 300)
                            Picker("Purpose", selection: $m.purpose) { ForEach(Purpose.allCases) { Text($0.rawValue).tag($0) } }.frame(width: 220)
                            Picker("Platform", selection: $m.platform) { ForEach(Platform.allCases) { Text($0.rawValue).tag($0) } }.frame(width: 280)
                        }
                        HStack {
                            SecureField(Checker.pfxSupported ? "PFX/P12 password (used once, not stored)" : "PFX/P12 needs macOS 15 or later", text: $m.password).frame(maxWidth: 300).disabled(!Checker.pfxSupported)
                            Spacer()
                            Button("Check files") { m.checkFiles() }.buttonStyle(.borderedProminent).tint(accent).disabled(m.files.isEmpty)
                        }
                        Text("Drop files on this panel or choose them. Supported: PEM bundles, DER .cer/.crt, PKCS#7 .p7b, CSR, unencrypted PKCS#1/PKCS#8/SEC1 keys, PFX/P12 (macOS 15 or later only: opened in memory, never imported into a keychain; refused on macOS 14).").font(.caption).foregroundStyle(.secondary)
                    }.padding(6)
                }
                if let r = m.report {
                    ResultsView(findings: r.findings, chain: r.chain, platform: m.platform, target: nil, extra: r.keyFormats.isEmpty ? nil : "Keys inspected in memory: " + r.keyFormats.joined(separator: ", "))
                }
            }.padding(28)
        }
        .onDisappear { m.password = "" }
    }
}

struct TargetsView: View {
    @EnvironmentObject var m: Checker
    var body: some View {
        HSplitView {
            VStack(alignment: .leading, spacing: 0) {
                HStack {
                    Text("Targets").font(.headline)
                    Spacer()
                    Button { m.editing = Target(name: "", host: "", service: .https) } label: { Image(systemName: "plus") }.help("Add target")
                    Button("Check all") { m.checkAll() }.disabled(m.targets.isEmpty || m.anyRunning)
                }.padding(12)
                List(selection: $m.selected) {
                    ForEach(m.targets) { t in
                        HStack {
                            statusIcon(m.status[t.id])
                            VStack(alignment: .leading) { Text(t.name.isEmpty ? t.host : t.name).fontWeight(.medium); Text("\(t.service.rawValue) · \(t.endpoint)").font(.caption).foregroundStyle(.secondary) }
                        }.tag(t.id)
                        .contextMenu { Button("Check") { m.check(t) }; Button("Edit…") { m.editing = t }; Button("Delete", role: .destructive) { m.delete(t) } }
                    }
                }
                if m.targets.isEmpty { Text("Add a service to check — for example the DC on LDAPS 636 or the mail server on 587.").font(.caption).foregroundStyle(.secondary).padding(12) }
            }.frame(minWidth: 280, idealWidth: 320, maxWidth: 420)
            ScrollView {
                if let id = m.selected, let t = m.targets.first(where: { $0.id == id }) { TargetDetail(target: t).padding(24) }
                else { VStack(spacing: 10) { Image(systemName: "network.badge.shield.half.filled").font(.system(size: 40)).foregroundStyle(.secondary); Text("Select a target, or Check all.").foregroundStyle(.secondary) }.frame(maxWidth: .infinity).padding(.top, 120) }
            }.frame(minWidth: 520)
        }
    }
    @ViewBuilder func statusIcon(_ s: TargetStatus?) -> some View {
        if s?.running == true { ProgressView().controlSize(.small).frame(width: 18) }
        else if let r = s?.result { SeverityIcon(severity: r.worst) }
        else { Image(systemName: "circle.dashed").foregroundStyle(.secondary).frame(width: 18) }
    }
}

struct TargetDetail: View {
    @EnvironmentObject var m: Checker
    let target: Target
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(target.name.isEmpty ? target.host : target.name).font(.system(size: 26, weight: .semibold, design: .rounded))
                    Text("\(target.service.rawValue) · \(target.endpoint) · SNI \(target.serverName) · verify \(target.verifyName) · \(target.platform.rawValue)").font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                }
                Spacer()
                Button("Edit…") { m.editing = target }
                Button("Check now") { m.check(target) }.buttonStyle(.borderedProminent).tint(accent).disabled(m.status[target.id]?.running == true)
            }
            if let u = WorkbenchHandoff.url(for: target) {
                HStack {
                    Image(systemName: "point.3.connected.trianglepath.dotted")
                    Text("Connection problem? Hand off to Connection Workbench.").font(.callout)
                    Button("Copy URL & open Workbench") {
                        NSPasteboard.general.clearContents(); NSPasteboard.general.setString(u, forType: .string)
                        let cfg = NSWorkspace.OpenConfiguration()
                        if let app = NSWorkspace.shared.urlForApplication(withBundleIdentifier: WorkbenchHandoff.bundleID) ?? WorkbenchHandoff.appURL.flatMap { FileManager.default.fileExists(atPath: $0.path) ? $0 : nil } {
                            NSWorkspace.shared.openApplication(at: app, configuration: cfg)
                        } else { m.message = "Connection Workbench was not found. The URL \(u) is on the clipboard." }
                    }
                }.padding(10).background(accent.opacity(0.06), in: RoundedRectangle(cornerRadius: 8))
            }
            if let r = m.status[target.id]?.result {
                Text("Checked \(r.started.formatted(date: .omitted, time: .standard)) in \(String(format: "%.2f", r.duration))s\(r.tlsVersion.map { " · \($0)" } ?? "")").font(.caption).foregroundStyle(.secondary)
                ResultsView(findings: r.findings, chain: r.chain, platform: target.platform, target: target, extra: nil)
                if !r.transcript.isEmpty {
                    DisclosureGroup("Protocol transcript") { Text(r.transcript.joined(separator: "\n")).font(.system(.caption, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }
                }
            } else if m.status[target.id]?.running == true { ProgressView("Checking…") }
            CommandRow(command: Probe.opensslCommand(target), caption: "Reproduce manually (copy-only)")
        }
    }
}

struct ResultsView: View {
    let findings: [Finding]; let chain: [Certificate]; let platform: Platform; let target: Target?; let extra: String?; var identifier: String? = nil
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            let counts = Dictionary(grouping: findings, by: \.severity).mapValues(\.count)
            HStack(spacing: 14) { ForEach(Severity.allCases.reversed(), id: \.self) { s in Label("\(counts[s] ?? 0) \(s.label)", systemImage: SeverityIcon.symbol(s)).foregroundStyle(SeverityIcon.color(s)) } }.font(.callout.weight(.medium))
            if let extra { Text(extra).font(.caption).foregroundStyle(.secondary) }
            GroupBox("Findings") {
                VStack(alignment: .leading, spacing: 8) { ForEach(findings) { FindingRow(finding: $0, platform: platform, target: target, identifier: identifier) } }.frame(maxWidth: .infinity, alignment: .leading).padding(4)
            }
            if !chain.isEmpty {
                GroupBox("Certificate chain (leaf first)") {
                    VStack(alignment: .leading, spacing: 10) { ForEach(Array(chain.enumerated()), id: \.offset) { i, c in CertCard(index: i, cert: c) } }.frame(maxWidth: .infinity, alignment: .leading).padding(4)
                }
            }
        }
    }
}

struct FindingRow: View {
    let finding: Finding; let platform: Platform; let target: Target?; var identifier: String? = nil
    @State private var open = false
    var body: some View {
        let guidance = (finding.severity < .warning && finding.kind != "install") ? [] : finding.topic == .wireguard ? WGAdvisor.guidance(for: finding, platform: platform) : finding.topic == .ipsec ? IPsecAdvisor.guidance(for: finding, platform: platform, identifier: identifier) : finding.topic == .radius ? RadiusAdvisor.guidance(for: finding, platform: platform) : finding.topic == .remote ? RemoteAdvisor.guidance(for: finding, target: target) : Advisor.guidance(for: finding.topic, platform: platform, target: target)
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .top) {
                SeverityIcon(severity: finding.severity)
                VStack(alignment: .leading, spacing: 2) {
                    Text(finding.title).fontWeight(.medium)
                    if !finding.detail.isEmpty { Text(finding.detail).font(.caption).foregroundStyle(.secondary).textSelection(.enabled) }
                }
                Spacer()
                if !guidance.isEmpty { Button(open ? "Hide fix" : "How to fix") { open.toggle() }.controlSize(.small) }
            }
            if open { ForEach(guidance) { GuidanceView(g: $0) }.padding(.leading, 26) }
        }
    }
}

struct GuidanceView: View {
    let g: Guidance
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(g.title).font(.callout.weight(.semibold))
            ForEach(Array(g.steps.enumerated()), id: \.offset) { i, s in Text("\(i + 1). \(s)").font(.callout) }
            ForEach(g.commands, id: \.self) { CommandRow(command: $0, caption: nil) }
            let docs = KB.available(g.docs)
            if !docs.isEmpty {
                HStack { Text("KB:").font(.caption).foregroundStyle(.secondary); ForEach(docs, id: \.self) { d in Button(KB.label(d)) { if let u = KB.url(d) { NSWorkspace.shared.open(u) } }.buttonStyle(.link).font(.caption) } }
            }
        }.padding(10).background(Color.secondary.opacity(0.07), in: RoundedRectangle(cornerRadius: 8))
    }
}

struct CommandRow: View {
    let command: String; let caption: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            if let caption { Text(caption).font(.caption).foregroundStyle(.secondary) }
            HStack {
                Text(command).font(.system(.caption, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                Button { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(command, forType: .string) } label: { Image(systemName: "doc.on.doc") }.buttonStyle(.borderless).help("Copy — the app never runs this command")
            }.padding(6).background(Color.black.opacity(0.06), in: RoundedRectangle(cornerRadius: 6))
        }
    }
}

struct CertCard: View {
    let index: Int; let cert: Certificate
    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text("\(index == 0 ? "Leaf" : "#\(index + 1)") · \(cert.displayName)").fontWeight(.semibold)
            Group {
                Text("Subject: \(cert.subject.text)")
                Text("Issuer: \(cert.issuer.text)")
                Text("Valid: \(Analysis.fmt(cert.notBefore)) → \(Analysis.fmt(cert.notAfter))")
                Text("Key: \(cert.publicKey.algorithm.description) · Signature: \(cert.signatureAlgorithm) · CA: \(cert.isCA == true ? "yes" : "no")")
                if !(cert.dnsNames + cert.ipAddresses).isEmpty { Text("SAN: \((cert.dnsNames + cert.ipAddresses).joined(separator: ", "))") }
                if let eku = cert.extendedKeyUsage { Text("EKU: \(eku.map(OID.name).joined(separator: ", "))") }
                Text("SHA-256: \(cert.sha256)")
                if let pin = cert.publicKey.spkiSHA256 { Text("SPKI pin (sha256/base64): \(pin)") }
            }.font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary).textSelection(.enabled)
        }.padding(8).frame(maxWidth: .infinity, alignment: .leading).background(Color.secondary.opacity(0.05), in: RoundedRectangle(cornerRadius: 8))
    }
}

struct SeverityIcon: View {
    let severity: Severity
    static func symbol(_ s: Severity) -> String { ["checkmark.circle.fill", "info.circle.fill", "exclamationmark.triangle.fill", "xmark.octagon.fill"][s.rawValue] }
    static func color(_ s: Severity) -> Color { [Color.green, Color.blue, Color.orange, Color.red][s.rawValue] }
    var body: some View { Image(systemName: Self.symbol(severity)).foregroundStyle(Self.color(severity)).frame(width: 18) }
}

struct TargetEditor: View {
    @EnvironmentObject var m: Checker
    @State var target: Target
    @State private var portText = ""
    var body: some View {
        Form {
            TextField("Name", text: $target.name)
            TextField("Host or IP", text: $target.host)
            Picker("Service", selection: $target.service) { ForEach(Service.allCases) { Text($0.rawValue).tag($0) } }
                .onChange(of: target.service) { _, s in target.port = s.defaultPort; portText = String(s.defaultPort) }
            TextField("Port", text: $portText).onChange(of: portText) { _, v in if let p = Int(v) { target.port = p } }
            TextField("SNI override (optional)", text: $target.sni)
            TextField("Expected certificate name (optional)", text: $target.expectedName)
            Picker("Platform (for fix guidance)", selection: $target.platform) { ForEach(Platform.allCases) { Text($0.rawValue).tag($0) } }
            TextField("Notes", text: $target.notes, axis: .vertical).lineLimit(2...4)
            Text("Targets are saved to ~/Library/Application Support/CertificateChecker/targets.json (0600). Results are not saved.").font(.caption).foregroundStyle(.secondary)
            HStack { Spacer(); Button("Cancel") { m.editing = nil }; Button("Save") { m.commit(target) }.keyboardShortcut(.defaultAction) }
        }.padding(20).frame(width: 480).onAppear { portText = String(target.port) }
    }
}

struct WireGuardView: View {
    @EnvironmentObject var m: Checker
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("Check WireGuard configs.").font(.system(size: 30, weight: .semibold, design: .rounded))
                Text("Key format, public/private match, peer keys, PresharedKey, AllowedIPs overlaps and Endpoint syntax. Offline only: nothing is sent, no UDP packets.").foregroundStyle(.secondary)
                GroupBox {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack {
                            Button("Choose files…") {
                                let p = NSOpenPanel(); p.allowsMultipleSelection = true; p.canChooseDirectories = false
                                p.message = "Choose wg-quick .conf files and/or a pfSense config.xml. Files are read in memory only."
                                if p.runModal() == .OK { m.wgFiles = p.urls; m.wgFindings = nil }
                            }
                            Text(m.wgFiles.isEmpty ? "No files selected" : m.wgFiles.map(\.lastPathComponent).joined(separator: ", ")).foregroundStyle(.secondary).lineLimit(2)
                        }
                        HStack {
                            TextField("Expected interface public key (optional)", text: $m.wgExpected).frame(maxWidth: 420)
                            Picker("Platform", selection: $m.wgPlatform) { Text("pfSense").tag(Platform.pfSense); Text("Linux wg-quick").tag(Platform.generic); Text("macOS app").tag(Platform.macOS) }.frame(width: 260)
                            Spacer()
                            Button("Check") { m.checkWireGuard() }.buttonStyle(.borderedProminent).tint(accent).disabled(m.wgFiles.isEmpty)
                        }
                        Text("Select both ends of a tunnel to verify that each lists the other's public key. Private keys are used only to derive public keys and are never shown, logged or saved.").font(.caption).foregroundStyle(.secondary)
                    }.padding(6)
                }
                if let f = m.wgFindings {
                    if !m.wgSummary.isEmpty { Text(m.wgSummary).font(.system(.caption, design: .monospaced)).textSelection(.enabled) }
                    ResultsView(findings: f, chain: [], platform: m.wgPlatform, target: nil, extra: nil)
                }
            }.padding(28)
        }
    }
}

struct IPsecView: View {
    @EnvironmentObject var m: Checker
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("Check IKEv2 certificates.").font(.system(size: 30, weight: .semibold, design: .rounded))
                Text("Server and CA certificates exported from pfSense Cert. Manager, or a config.xml backup: serverAuth/IKE EKUs, SAN, keyUsage, key and digest strength, lifetime, CA chain and key match. Offline only: no IKE packets are sent.").foregroundStyle(.secondary)
                GroupBox {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack {
                            Button("Choose files…") {
                                let p = NSOpenPanel(); p.allowsMultipleSelection = true; p.canChooseDirectories = false
                                p.message = "Choose server/CA certificates (.crt/.pem), optional private key, or a pfSense config.xml. Files are read in memory only."
                                if p.runModal() == .OK { m.ipFiles = p.urls; m.ipFindings = nil }
                            }
                            Text(m.ipFiles.isEmpty ? "No files selected" : m.ipFiles.map(\.lastPathComponent).joined(separator: ", ")).foregroundStyle(.secondary).lineLimit(2)
                        }
                        HStack {
                            TextField("Server FQDN or IP clients use (Remote ID)", text: $m.ipIdentifier).frame(maxWidth: 360)
                            Picker("Guidance", selection: $m.ipPlatform) { Text("pfSense first").tag(Platform.pfSense); Text("Windows client first").tag(Platform.windowsIIS); Text("macOS/iOS first").tag(Platform.macOS) }.frame(width: 260)
                            Spacer()
                            Button("Check") { m.checkIPsec() }.buttonStyle(.borderedProminent).tint(accent).disabled(m.ipFiles.isEmpty)
                        }
                        Text("Private keys (PEM or config.xml <prv>) are used only to confirm they match and are never shown, logged or saved. A config.xml contains every private key on the firewall: keep it off synced folders.").font(.caption).foregroundStyle(.secondary)
                    }.padding(6)
                }
                if let f = m.ipFindings { ResultsView(findings: f, chain: m.ipChain, platform: m.ipPlatform, target: nil, extra: nil, identifier: m.ipIdentifier) }
            }.padding(28)
        }
    }
}

struct RadiusView: View {
    @EnvironmentObject var m: Checker
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("Check RADIUS certificates.").font(.system(size: 30, weight: .semibold, design: .rounded))
                Text("EAP-TLS / PEAP server certificate: serverAuth EKU, the name clients expect, key and digest strength, chain to the trusted CA and lifetime.").foregroundStyle(.secondary)
                GroupBox("Offline: certificate files") {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack {
                            Button("Choose files…") {
                                let p = NSOpenPanel(); p.allowsMultipleSelection = true; p.canChooseDirectories = false
                                p.message = "Choose the RADIUS server certificate, its CA chain and optionally its private key. Read in memory only."
                                if p.runModal() == .OK { m.radFiles = p.urls; m.radFindings = nil }
                            }
                            Text(m.radFiles.isEmpty ? "No files selected" : m.radFiles.map(\.lastPathComponent).joined(separator: ", ")).foregroundStyle(.secondary).lineLimit(2)
                            Spacer()
                            Button("Check files") { m.checkRadiusFiles() }.buttonStyle(.borderedProminent).tint(accent).disabled(m.radFiles.isEmpty)
                        }
                        HStack {
                            TextField("Server name clients expect (e.g. \(AppConfig.current.radiusHostPlaceholder))", text: $m.radName).frame(maxWidth: 360)
                            Picker("Guidance", selection: $m.radPlatform) { Text("Windows NPS").tag(Platform.windowsAD); Text("FreeRADIUS on Linux").tag(Platform.generic); Text("pfSense FreeRADIUS").tag(Platform.pfSense) }.frame(width: 280)
                        }
                    }.padding(6)
                }
                GroupBox("Live: one eapol_test attempt") {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack {
                            TextField("RADIUS server host or IP", text: $m.radHost).frame(maxWidth: 260)
                            TextField("Port", text: $m.radPort).frame(width: 70)
                            Picker("EAP", selection: $m.radMethod) { ForEach(EAPMethod.allCases) { Text($0.rawValue).tag($0) } }.frame(width: 140)
                            SecureField("Shared secret", text: $m.radSecret).frame(width: 200)
                            Button(m.radRunning ? "Probing…" : "Probe once") { m.probeRadius() }.disabled(m.radRunning || m.radHost.isEmpty || m.radSecret.isEmpty)
                        }
                        Text("Sends one EAP exchange with an anonymous identity and dummy credentials (authentication is expected to fail) and keeps the certificate chain the server presents. The shared secret is used once and never saved; eapol_test receives it as a command-line argument. This Mac must be a RADIUS client on the server: add a probe-only client entry for this Mac with its own shared secret (not the access points’ secret), and remove it when you are done. \(RadiusProbe.locate() == nil ? "eapol_test is not installed: the probe will be skipped." : "")").font(.caption).foregroundStyle(.secondary)
                    }.padding(6)
                }
                if !m.radTranscript.isEmpty { Text(m.radTranscript.joined(separator: "\n")).font(.system(.caption, design: .monospaced)).textSelection(.enabled) }
                if let f = m.radFindings { ResultsView(findings: f, chain: m.radChain, platform: m.radPlatform, target: nil, extra: nil) }
            }.padding(28)
        }
    }
}

struct RemoteView: View {
    @EnvironmentObject var m: Checker
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("Check remote access certificates.").font(.system(size: 30, weight: .semibold, design: .rounded))
                Text("RDP (X.224 negotiation, then the TLS handshake), RD Gateway (HTTPS) and WinRM (HTTPS 5986): EKU (Server Authentication or Remote Desktop Authentication for RDP), name coverage, self-signed defaults, key and digest strength, expiry and trust. One attempt; no credentials and nothing beyond the TLS layer.").foregroundStyle(.secondary)
                GroupBox {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack {
                            Picker("Service", selection: Binding(get: { m.rem.service }, set: { m.rem.select($0) })) {
                                Text("RDP (3389)").tag(Service.rdp); Text("RD Gateway (443)").tag(Service.rdGateway); Text("WinRM HTTPS (5986)").tag(Service.winrmHTTPS)
                            }.frame(width: 260)
                            TextField("Host or IP (e.g. \(AppConfig.current.hostPlaceholder))", text: $m.rem.host).frame(maxWidth: 280)
                            TextField("Port", text: $m.rem.port).frame(width: 70)
                        }
                        HStack {
                            TextField("Expected certificate name (optional)", text: $m.rem.expected).frame(maxWidth: 320)
                            Spacer()
                            Button("Add to Targets") { m.addRemoteTarget() }.disabled(!m.rem.canRun)
                            Button(m.remRunning ? "Checking…" : "Check once") { m.probeRemote() }.buttonStyle(.borderedProminent).tint(accent).disabled(m.remRunning || !m.rem.canRun)
                        }
                        if m.rem.service == .winrmHTTPS {
                            Toggle("Also check the WinRM HTTP listener on 5985 (plaintext: sends one unauthenticated POST /wsman)", isOn: $m.rem.checkHTTP)
                            if m.rem.checkHTTP { Label("HTTP is unencrypted. Only the listener and its offered authentication schemes are reported; no credentials are sent.", systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange) }
                        }
                        Text("Guidance is copy-only PowerShell with THUMBPRINT placeholders. Restrict RDP and WinRM to admin networks; publish RDP through RD Gateway.").font(.caption).foregroundStyle(.secondary)
                    }.padding(6)
                }
                if let r = m.remResult, let t = m.remTarget {
                    Text("Checked \(t.endpoint) in \(String(format: "%.2f", r.duration))s\(r.tlsVersion.map { " · \($0)" } ?? "")").font(.caption).foregroundStyle(.secondary)
                    ResultsView(findings: r.findings, chain: r.chain, platform: t.platform, target: t, extra: nil)
                    if !r.transcript.isEmpty { DisclosureGroup("Protocol transcript") { Text(r.transcript.joined(separator: "\n")).font(.system(.caption, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) } }
                    CommandRow(command: Probe.opensslCommand(t), caption: "Reproduce manually (copy-only)")
                }
            }.padding(28)
        }
    }
}
