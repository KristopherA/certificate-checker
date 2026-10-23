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
                let h = await WinRMHTTP.check(host: t.host, connect: t.connectOverride)
                r.transcript += h.transcript
                r.findings = (r.findings + h.findings).sorted { $0.severity == $1.severity ? $0.id < $1.id : $0.severity > $1.severity }
            }
            remResult = r; remRunning = false
        }
    }
    // Appliances (Synology DSM, Proxmox VE, Proxmox Backup Server)
    @Published var appl = ApplianceForm()
    @Published var applRunning = false
    @Published var applResult: ProbeResult?
    @Published var applTarget: Target?
    func probeAppliance() {
        let t = appl.target
        do { try t.validate() } catch { message = error.localizedDescription; return }
        applRunning = true; applTarget = t; applResult = nil
        Task { let r = await Probe.run(t); applResult = r; applRunning = false }
    }
    func addApplianceTarget() { var t = appl.target; t.name = "\(appl.service.rawValue) \(t.host)"; if commit(t) { section = 1 } }
    // Registry & Beats (Docker registry, Logstash Beats input, Elasticsearch, Beats client mTLS pair)
    @Published var stk = StackForm()
    @Published var stkCA: [URL] = []
    @Published var stkRunning = false
    @Published var stkResult: ProbeResult?
    @Published var stkTarget: Target?
    @Published var pairFiles: [URL] = []
    @Published var pairFindings: [Finding]?
    @Published var pairChain: [Certificate] = []
    func probeStack() {
        let t = stk.target, v2 = stk.runsV2, ca = stkCA
        do { try t.validate() } catch { message = error.localizedDescription; return }
        let anchors: [Certificate]
        do { anchors = ca.isEmpty ? [] : try Stack.loadCA(ca) } catch { message = error.localizedDescription; return }
        stkRunning = true; stkTarget = t; stkResult = nil
        Task {
            var r = await Probe.run(t, registryAPI: v2)
            if !anchors.isEmpty && !r.chain.isEmpty { r.findings = Stack.suppliedCA(r.findings, chain: r.chain, ca: anchors, hostname: t.verifyName) }
            stkResult = r; stkRunning = false
        }
    }
    func checkPair() {
        let urls = pairFiles, ca = stkCA
        Task {
            let r = await Task.detached { MTLSPair.inspect(urls, ca: ca) }.value
            pairFindings = r.findings; pairChain = r.chain
        }
    }
    // Services & devices (FileMaker, Retrospect, HP printer EWS, Barracuda WAF, Munki repo) and Munki ManagedInstalls offline
    @Published var vnd = VendorForm()
    @Published var vndRunning = false
    @Published var vndResult: ProbeResult?
    @Published var vndTarget: Target?
    @Published var munkiPlist: URL?
    @Published var munkiOverrides: [URL] = []
    @Published var munkiCA: URL?
    @Published var munkiProbe = false
    @Published var munkiRunning = false
    @Published var munkiFindings: [Finding]?
    @Published var munkiChain: [Certificate] = []
    func probeVendor() {
        let t = vnd.target
        do { try t.validate() } catch { message = error.localizedDescription; return }
        vndRunning = true; vndTarget = t; vndResult = nil
        Task { let r = await Probe.run(t); vndResult = r; vndRunning = false }
    }
    func addVendorTarget() { var t = vnd.target; t.name = "\(vnd.service.rawValue) \(t.host)"; if commit(t) { section = 1 } }
    func checkMunki() {
        guard let plist = munkiPlist else { return }
        let files = munkiOverrides, ca = munkiCA, probe = munkiProbe
        munkiRunning = true; munkiFindings = nil
        Task {
            let r: (chain: [Certificate], findings: [Finding]) = await Task.detached {
                do {
                    let s = try Munki.load(plist)
                    // Overrides are sorted by content (PEM private key vs certificate), not by panel order.
                    let o = try Munki.classifyOverrides(files)
                    return Munki.inspect(s, cert: o.cert, key: o.key, ca: ca)
                } catch { return ([], [Finding("munki-plist", .fail, .vendor, "Could not read \(plist.lastPathComponent)", error.localizedDescription)]) }
            }.value
            var findings = r.findings
            if probe {
                let loaded: Result<MunkiSettings, Error> = Result { try Munki.load(plist) }
                switch loaded {
                case .failure(let e): findings.append(Finding("munki-plist-read", .fail, .vendor, "Could not re-read \(plist.lastPathComponent) for the repo probe", e.localizedDescription))
                case .success(let s):
                if let t = s.repoTarget {
                    var p = await Probe.run(t)
                    if let caURL = ca ?? s.caCertificate.map({ URL(fileURLWithPath: $0) }), !p.chain.isEmpty {
                        do { p.findings = Stack.suppliedCA(p.findings, chain: p.chain, ca: try Stack.loadCA([caURL]), hostname: t.verifyName) }
                        catch { p.findings.append(Finding("munki-ca-read", .fail, .vendor, "Could not read SoftwareRepoCACertificate", error.localizedDescription)) }
                    }
                    findings += p.findings.map { var g = $0; g.title = "Repo: " + g.title; return g }
                } else { findings.append(Finding("munki-probe", .info, .vendor, "Repo not probed", "SoftwareRepoURL is not an https:// URL with a host.")) }
            }
            }
            munkiFindings = findings; munkiChain = r.chain; munkiRunning = false
        }
    }
    func addStackTarget() { var t = stk.target; t.name = "\(stk.service.rawValue) \(t.host)"; if commit(t) { section = 1 } }
    func addRemoteTarget() { var t = rem.target; t.name = "\(rem.service.rawValue) \(t.host)"; if commit(t) { section = 1 } }
    // Targets
    @Published var targets: [Target] = []
    @Published var status: [UUID: TargetStatus] = [:]
    @Published var selected: UUID?
    @Published var editing: Target?
    @Published var message: String?
    var library = TargetLibrary()
    var targetsLoadError: String? { library.loadError }
    static var pfxSupported: Bool { if #available(macOS 15.0, *) { return true } else { return false } }

    init() { targets = library.targets; if let e = library.loadError { message = e } }

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
    func save() { do { try library.save(targets) } catch { message = error.localizedDescription } }
    @discardableResult func commit(_ t: Target) -> Bool {
        if let e = library.loadError { message = e; return false }
        do {
            try t.validate()
            try library.upsert(t); targets = library.targets
            editing = nil; selected = t.id; return true
        } catch { message = error.localizedDescription; return false }
    }
    func delete(_ t: Target) {
        if let e = library.loadError { message = e; return }
        do { try library.delete(id: t.id) } catch { message = error.localizedDescription; return }
        targets = library.targets; status[t.id] = nil; if selected == t.id { selected = nil }
    }
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
                rail(6, "externaldrive.connected.to.line.below", "Appliances", "Synology DSM, Proxmox VE, PBS")
                rail(7, "shippingbox", "Registry & Beats", "Docker registry, Logstash, Elasticsearch, mTLS")
                rail(8, "printer", "Services & devices", "Munki, FileMaker, Retrospect, HP printer, Barracuda WAF")
                Spacer()
                Label("On demand only", systemImage: "hand.tap").font(.caption)
                Text("Nothing runs in the background. Private keys are read in memory only and never logged, cached, copied or uploaded. Fix commands are copy-only.").font(.caption).foregroundStyle(.secondary)
                Text("macOS 14+ · v0.10.0\(AppConfig.current.organizationName.isEmpty ? "" : " · " + AppConfig.current.organizationName)").font(.caption2).foregroundStyle(.secondary)
                Text("Config: \(AppConfig.source == "built-in defaults" ? "built-in defaults" : (AppConfig.source as NSString).abbreviatingWithTildeInPath)\(AppConfig.loadError == nil ? "" : " (error, defaults used)")").font(.caption2).foregroundStyle(.secondary).lineLimit(2).help(AppConfig.loadError ?? AppConfig.source).textSelection(.enabled)
            }.padding(24).frame(width: 230).frame(maxHeight: .infinity).background(accent.opacity(0.055))
            Divider()
            Group { if m.section == 0 { FilesView() } else if m.section == 1 { TargetsView() } else if m.section == 2 { WireGuardView() } else if m.section == 3 { IPsecView() } else if m.section == 4 { RadiusView() } else if m.section == 5 { RemoteView() } else if m.section == 6 { ApplianceView() } else if m.section == 7 { StackView() } else { VendorView() } }.frame(maxWidth: .infinity, maxHeight: .infinity)
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
                    if let e = m.targetsLoadError { Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red).help(e) }
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
        let guidance = (finding.severity < .warning && finding.kind != "install") ? [] : finding.topic == .wireguard ? WGAdvisor.guidance(for: finding, platform: platform) : finding.topic == .ipsec ? IPsecAdvisor.guidance(for: finding, platform: platform, identifier: identifier) : finding.topic == .radius ? RadiusAdvisor.guidance(for: finding, platform: platform) : finding.topic == .remote ? RemoteAdvisor.guidance(for: finding, target: target) : finding.topic == .appliance ? ApplianceAdvisor.guidance(for: finding, target: target) : finding.topic == .stack ? StackAdvisor.guidance(for: finding, target: target) : finding.topic == .vendor ? VendorAdvisor.guidance(for: finding, target: target) : Advisor.guidance(for: finding.topic, platform: platform, target: target)
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
                .onChange(of: target.service) { _, s in target.port = s.defaultPort; portText = String(s.defaultPort); if !s.acceptsFingerprintPin { target.fingerprintPin = nil } }
            TextField("Port", text: $portText).onChange(of: portText) { _, v in if let p = Int(v) { target.port = p } }
            TextField("SNI override (optional)", text: $target.sni)
            TextField("Expected certificate name (optional)", text: $target.expectedName)
            TextField("Connect IP (optional, bypasses DNS; SNI stays the host)", text: Binding(get: { target.connectIP ?? "" }, set: { target.connectIP = $0.trimmingCharacters(in: .whitespaces).isEmpty ? nil : $0.trimmingCharacters(in: .whitespaces) }))
            if target.service.acceptsFingerprintPin { TextField("Fingerprint pin, SHA-256 AA:BB:… (optional)", text: Binding(get: { target.fingerprintPin ?? "" }, set: { target.fingerprintPin = $0.isEmpty ? nil : $0 })) }
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

struct ApplianceView: View {
    @EnvironmentObject var m: Checker
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("Check appliance certificates.").font(.system(size: 30, weight: .semibold, design: .rounded))
                Text("Synology DSM (5001), Proxmox VE (8006) and Proxmox Backup Server (8007): expiry, chain, SAN coverage, self-signed and factory/default certificates, key and digest strength, trust, and for PBS a comparison of the served SHA-256 fingerprint with your pin. One attempt; TLS handshake only, no HTTP request and no login.").foregroundStyle(.secondary)
                GroupBox {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack {
                            Picker("Product", selection: Binding(get: { m.appl.service }, set: { m.appl.select($0) })) {
                                Text("Synology DSM (5001)").tag(Service.synologyDSM); Text("Proxmox VE (8006)").tag(Service.proxmoxVE); Text("Proxmox Backup Server (8007)").tag(Service.proxmoxBackup)
                            }.frame(width: 300)
                            TextField("Host or IP (e.g. \(AppConfig.current.hostPlaceholder))", text: $m.appl.host).frame(maxWidth: 280)
                            TextField("Port", text: $m.appl.port).frame(width: 70)
                        }
                        HStack {
                            TextField("Expected certificate name (optional)", text: $m.appl.expected).frame(maxWidth: 320)
                            Spacer()
                            Button("Add to Targets") { m.addApplianceTarget() }.disabled(!m.appl.canRun)
                            Button(m.applRunning ? "Checking…" : "Check once") { m.probeAppliance() }.buttonStyle(.borderedProminent).tint(accent).disabled(m.applRunning || !m.appl.canRun)
                        }
                        if m.appl.service.acceptsFingerprintPin {
                            TextField("Fingerprint pin (SHA-256, AA:BB:…; optional)", text: $m.appl.fingerprint).font(.system(.body, design: .monospaced))
                            Text("Copy it from the PBS dashboard (Show Fingerprint) / proxmox-backup-manager cert info, or pvenode cert info on a PVE node. A fingerprint is public; never paste a private key here.").font(.caption).foregroundStyle(.secondary)
                        }
                        Text("Guidance is copy-only (DSM Control Panel steps, pvenode, proxmox-backup-manager, pvesm). Nothing is executed.").font(.caption).foregroundStyle(.secondary)
                    }.padding(6)
                }
                if let r = m.applResult, let t = m.applTarget {
                    Text("Checked \(t.endpoint) in \(String(format: "%.2f", r.duration))s\(r.tlsVersion.map { " · \($0)" } ?? "")").font(.caption).foregroundStyle(.secondary)
                    ResultsView(findings: r.findings, chain: r.chain, platform: t.platform, target: t, extra: nil)
                    if !r.transcript.isEmpty { DisclosureGroup("Protocol transcript") { Text(r.transcript.joined(separator: "\n")).font(.system(.caption, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) } }
                    CommandRow(command: Probe.opensslCommand(t), caption: "Reproduce manually (copy-only)")
                }
            }.padding(28)
        }
    }
}

struct VendorView: View {
    @EnvironmentObject var m: Checker
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("Check service and device certificates.").font(.system(size: 30, weight: .semibold, design: .rounded))
                Text("FileMaker Server (443 / 5003), Retrospect web console (443 / 8443), HP printer EWS (443), Barracuda WAF service listeners (443) and management UI (8443), and Munki repos: expiry, chain, SAN coverage, vendor default certificates, key and digest strength, negotiated protocol and trust. One TLS handshake; trust evaluation never fetches from the network. The Retrospect Engine (22024) and Client (497) ports are not TLS and are not checked.").foregroundStyle(.secondary)
                GroupBox("Server certificate") {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack {
                            Picker("Product", selection: Binding(get: { m.vnd.service }, set: { m.vnd.select($0) })) {
                                ForEach(VendorForm.services, id: \.self) { s in Text("\(s.rawValue) · \(s.defaultPort)").tag(s) }
                            }.frame(width: 340)
                            TextField("Host or IP (e.g. \(AppConfig.current.hostPlaceholder))", text: $m.vnd.host).frame(maxWidth: 260)
                            TextField("Port", text: $m.vnd.port).frame(width: 70)
                        }
                        HStack {
                            TextField("Expected certificate name (optional)", text: $m.vnd.expected).frame(maxWidth: 320)
                            Spacer()
                            Button("Add to Targets") { m.addVendorTarget() }.disabled(!m.vnd.canRun)
                            Button(m.vndRunning ? "Checking…" : "Check once") { m.probeVendor() }.buttonStyle(.borderedProminent).tint(accent).disabled(m.vndRunning || !m.vnd.canRun)
                        }
                        Text("Guidance is copy-only (FileMaker Admin Console / fmsadmin, HP EWS menus, Barracuda BASIC › Certificates, Munki defaults). Nothing is executed.").font(.caption).foregroundStyle(.secondary)
                    }.padding(6)
                }
                if let r = m.vndResult, let t = m.vndTarget {
                    Text("Checked \(t.endpoint) in \(String(format: "%.2f", r.duration))s\(r.tlsVersion.map { " · \($0)" } ?? "")").font(.caption).foregroundStyle(.secondary)
                    ResultsView(findings: r.findings, chain: r.chain, platform: t.platform, target: t, extra: nil)
                    if !r.transcript.isEmpty { DisclosureGroup("Protocol transcript") { Text(r.transcript.joined(separator: "\n")).font(.system(.caption, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) } }
                    CommandRow(command: Probe.opensslCommand(t), caption: "Reproduce manually (copy-only)")
                    if t.service == .hpPrinter {
                        ForEach(VendorAdvisor.hp(host: t.verifyName).commands.prefix(2), id: \.self) { c in CommandRow(command: c, caption: "Old-protocol test (copy-only; one handshake each)") }
                    }
                }
                GroupBox("Munki: ManagedInstalls (offline) and repo") {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack {
                            Button("ManagedInstalls plist…") {
                                let p = NSOpenPanel(); p.allowsMultipleSelection = false; p.canChooseDirectories = false
                                p.message = "Choose a copy of /Library/Preferences/ManagedInstalls.plist. Read in memory only."
                                if p.runModal() == .OK { m.munkiPlist = p.url; m.munkiFindings = nil }
                            }
                            Text(m.munkiPlist?.lastPathComponent ?? "No plist selected").foregroundStyle(.secondary).lineLimit(1)
                            Button("Client cert + key…") {
                                let p = NSOpenPanel(); p.allowsMultipleSelection = true; p.canChooseDirectories = false
                                p.message = "Optional: the client certificate and/or its key (told apart by content), if the plist paths are not on this Mac. Read in memory only."
                                if p.runModal() == .OK { m.munkiOverrides = p.urls }
                            }
                            Button("CA file…") {
                                let p = NSOpenPanel(); p.allowsMultipleSelection = false; p.canChooseDirectories = false
                                p.message = "Optional: SoftwareRepoCACertificate, if its path is not on this Mac."
                                if p.runModal() == .OK { m.munkiCA = p.url }
                            }
                        }
                        HStack {
                            Toggle("Also check the repo TLS once (SoftwareRepoURL host)", isOn: $m.munkiProbe)
                            Spacer()
                            Button(m.munkiRunning ? "Checking…" : "Check Munki") { m.checkMunki() }.buttonStyle(.borderedProminent).tint(accent).disabled(m.munkiPlist == nil || m.munkiRunning)
                        }
                        Text("Reads SoftwareRepoURL, UseClientCertificate, ClientCertificatePath, ClientKeyPath and SoftwareRepoCACertificate; checks key match, clientAuth EKU and the chain. Configuration-profile (MDM) values are not read; a profile can override the plist. The client certificate is not presented in a handshake.").font(.caption).foregroundStyle(.secondary)
                    }.padding(6)
                }
                if let f = m.munkiFindings { ResultsView(findings: f, chain: m.munkiChain, platform: .munki, target: nil, extra: nil) }
            }.padding(28)
        }
    }
}

struct StackView: View {
    @EnvironmentObject var m: Checker
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text("Check registry and Beats certificates.").font(.system(size: 30, weight: .semibold, design: .rounded))
                Text("Docker registry (/v2/ on 443 or 5000), Logstash Beats input (5044) and Elasticsearch (9200): expiry, chain, SAN coverage, key and digest strength, and optionally the chain against the CA file your clients use. One TLS handshake; trust evaluation never fetches from the network.").foregroundStyle(.secondary)
                GroupBox("Server certificate") {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack {
                            Picker("Service", selection: Binding(get: { m.stk.service }, set: { m.stk.select($0) })) {
                                Text("Docker registry (443 / 5000)").tag(Service.dockerRegistry); Text("Logstash Beats input (5044)").tag(Service.logstashBeats); Text("Elasticsearch (9200)").tag(Service.elasticsearch)
                            }.frame(width: 300)
                            TextField("Host or IP (e.g. \(AppConfig.current.hostPlaceholder))", text: $m.stk.host).frame(maxWidth: 280)
                            TextField("Port", text: $m.stk.port).frame(width: 70)
                        }
                        HStack {
                            TextField("Expected certificate name (optional)", text: $m.stk.expected).frame(maxWidth: 320)
                            Button("CA file clients use…") {
                                let p = NSOpenPanel(); p.allowsMultipleSelection = true; p.canChooseDirectories = false
                                p.message = "Choose the CA file named by ssl.certificate_authorities (or /etc/docker/certs.d/…/ca.crt). Read in memory only."
                                if p.runModal() == .OK { m.stkCA = p.urls }
                            }
                            Text(m.stkCA.isEmpty ? "No CA file (optional)" : m.stkCA.map(\.lastPathComponent).joined(separator: ", ")).foregroundStyle(.secondary).lineLimit(1)
                            Spacer()
                            Button("Add to Targets") { m.addStackTarget() }.disabled(!m.stk.canRun)
                            Button(m.stkRunning ? "Checking…" : "Check once") { m.probeStack() }.buttonStyle(.borderedProminent).tint(accent).disabled(m.stkRunning || !m.stk.canRun)
                        }
                        if m.stk.service == .dockerRegistry {
                            Toggle("Also send one unauthenticated GET /v2/ (same TLS connection, no credentials)", isOn: $m.stk.checkV2)
                        }
                        Text("Guidance is copy-only (registry config.yml, /etc/docker/certs.d, Logstash beats input ssl_*, filebeat.yml ssl.*, elasticsearch.yml). Nothing is executed.").font(.caption).foregroundStyle(.secondary)
                    }.padding(6)
                }
                if let r = m.stkResult, let t = m.stkTarget {
                    Text("Checked \(t.endpoint) in \(String(format: "%.2f", r.duration))s\(r.tlsVersion.map { " · \($0)" } ?? "")").font(.caption).foregroundStyle(.secondary)
                    ResultsView(findings: r.findings, chain: r.chain, platform: t.platform, target: t, extra: nil)
                    if !r.transcript.isEmpty { DisclosureGroup("Protocol transcript") { Text(r.transcript.joined(separator: "\n")).font(.system(.caption, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) } }
                    CommandRow(command: Probe.opensslCommand(t), caption: "Reproduce manually (copy-only)")
                }
                GroupBox("Offline: Beats client certificate and key (mTLS)") {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack {
                            Button("Choose files…") {
                                let p = NSOpenPanel(); p.allowsMultipleSelection = true; p.canChooseDirectories = false
                                p.message = "Choose the Beats client certificate (ssl.certificate) and its key (ssl.key). Read in memory only."
                                if p.runModal() == .OK { m.pairFiles = p.urls; m.pairFindings = nil }
                            }
                            Text(m.pairFiles.isEmpty ? "No files selected" : m.pairFiles.map(\.lastPathComponent).joined(separator: ", ")).foregroundStyle(.secondary).lineLimit(2)
                            Spacer()
                            Button("Check pair") { m.checkPair() }.buttonStyle(.borderedProminent).tint(accent).disabled(m.pairFiles.isEmpty)
                        }
                        Text("Checks key match, the clientAuth EKU and the chain to the CA file chosen above (the CA the server trusts for clients). The client certificate is not presented in a live handshake: that would need the key imported into a keychain.").font(.caption).foregroundStyle(.secondary)
                    }.padding(6)
                }
                if let f = m.pairFindings { ResultsView(findings: f, chain: m.pairChain, platform: .elasticStack, target: nil, extra: nil) }
            }.padding(28)
        }
    }
}
