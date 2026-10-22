import AppKit
// Usage: icon <iconset-dir> <appiconset-dir> <preview.png>
// Draws the Certificate Checker icon: Big Sur rounded square, certificate sheet, ribbon seal with shield and checkmark.
let args = CommandLine.arguments
let iconset = URL(fileURLWithPath: args[1]), appiconset = URL(fileURLWithPath: args[2]), preview = URL(fileURLWithPath: args[3])
for d in [iconset, appiconset] { try FileManager.default.createDirectory(at: d, withIntermediateDirectories: true) }

func draw(_ pixels: Int) -> NSBitmapImageRep {
    let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: pixels, pixelsHigh: pixels, bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    let ctx = NSGraphicsContext(bitmapImageRep: bitmap)!
    NSGraphicsContext.current = ctx
    ctx.imageInterpolation = .high
    let t = NSAffineTransform(); t.scale(by: CGFloat(pixels) / 1024); t.concat()
    func rgb(_ r: CGFloat, _ g: CGFloat, _ b: CGFloat, _ a: CGFloat = 1) -> NSColor { NSColor(srgbRed: r/255, green: g/255, blue: b/255, alpha: a) }

    // Rounded square (Big Sur grid: 824pt body, 100pt margin) with soft shadow.
    let body = NSBezierPath(roundedRect: NSRect(x: 100, y: 100, width: 824, height: 824), xRadius: 186, yRadius: 186)
    NSGraphicsContext.saveGraphicsState()
    let sh = NSShadow(); sh.shadowColor = rgb(0, 0, 0, 0.30); sh.shadowBlurRadius = 28; sh.shadowOffset = NSSize(width: 0, height: -12); sh.set()
    rgb(20, 70, 150).setFill(); body.fill()
    NSGraphicsContext.restoreGraphicsState()
    NSGradient(starting: rgb(64, 150, 240), ending: rgb(14, 52, 128))!.draw(in: body, angle: -90)
    // Subtle top highlight
    NSGradient(starting: rgb(255, 255, 255, 0.18), ending: rgb(255, 255, 255, 0))!.draw(in: NSBezierPath(roundedRect: NSRect(x: 100, y: 520, width: 824, height: 404), xRadius: 186, yRadius: 186), angle: -90)

    // Certificate sheet
    let sheetRect = NSRect(x: 232, y: 300, width: 500, height: 520)
    let sheet = NSBezierPath(roundedRect: sheetRect, xRadius: 34, yRadius: 34)
    NSGraphicsContext.saveGraphicsState()
    let s2 = NSShadow(); s2.shadowColor = rgb(0, 0, 0, 0.28); s2.shadowBlurRadius = 22; s2.shadowOffset = NSSize(width: 0, height: -10); s2.set()
    rgb(250, 251, 253).setFill(); sheet.fill()
    NSGraphicsContext.restoreGraphicsState()
    // Inner border
    rgb(26, 86, 170, 0.35).setStroke()
    let border = NSBezierPath(roundedRect: sheetRect.insetBy(dx: 24, dy: 24), xRadius: 18, yRadius: 18); border.lineWidth = 6; border.stroke()
    // Title bar and text lines
    rgb(26, 86, 170).setFill(); NSBezierPath(roundedRect: NSRect(x: 312, y: 712, width: 340, height: 34), xRadius: 17, yRadius: 17).fill()
    rgb(150, 164, 186).setFill()
    for (y, w) in [(650.0, 340.0), (604.0, 300.0), (558.0, 320.0), (512.0, 200.0)] {
        NSBezierPath(roundedRect: NSRect(x: 312, y: y, width: w, height: 20), xRadius: 10, yRadius: 10).fill()
    }

    // Ribbon tails
    let cx: CGFloat = 664, cy: CGFloat = 360
    for dir: CGFloat in [-1, 1] {
        let tail = NSBezierPath()
        tail.move(to: NSPoint(x: cx + dir * 30, y: cy - 40))
        tail.line(to: NSPoint(x: cx + dir * 110, y: cy - 250))
        tail.line(to: NSPoint(x: cx + dir * 62, y: cy - 220))
        tail.line(to: NSPoint(x: cx + dir * 40, y: cy - 272))
        tail.line(to: NSPoint(x: cx - dir * 30, y: cy - 60))
        tail.close()
        (dir < 0 ? rgb(196, 40, 52) : rgb(170, 28, 42)).setFill(); tail.fill()
    }
    // Scalloped seal
    let seal = NSBezierPath()
    let points = 28
    for i in 0..<(points * 2) {
        let a = CGFloat(i) * .pi / CGFloat(points) + .pi / 2
        let r: CGFloat = i % 2 == 0 ? 168 : 150
        let p = NSPoint(x: cx + cos(a) * r, y: cy + sin(a) * r)
        if i == 0 { seal.move(to: p) } else { seal.line(to: p) }
    }
    seal.close()
    NSGraphicsContext.saveGraphicsState()
    let s3 = NSShadow(); s3.shadowColor = rgb(0, 0, 0, 0.35); s3.shadowBlurRadius = 18; s3.shadowOffset = NSSize(width: 0, height: -8); s3.set()
    rgb(232, 176, 44).setFill(); seal.fill()
    NSGraphicsContext.restoreGraphicsState()
    NSGradient(starting: rgb(255, 214, 92), ending: rgb(214, 146, 24))!.draw(in: seal, angle: -90)
    let inner = NSBezierPath(ovalIn: NSRect(x: cx - 124, y: cy - 124, width: 248, height: 248))
    NSGradient(starting: rgb(255, 226, 120), ending: rgb(226, 160, 34))!.draw(in: inner, angle: -90)
    rgb(176, 112, 10, 0.7).setStroke(); inner.lineWidth = 6; inner.stroke()

    // Shield
    let shield = NSBezierPath()
    shield.move(to: NSPoint(x: cx, y: cy + 98))
    shield.curve(to: NSPoint(x: cx + 82, y: cy + 66), controlPoint1: NSPoint(x: cx + 30, y: cy + 80), controlPoint2: NSPoint(x: cx + 56, y: cy + 70))
    shield.curve(to: NSPoint(x: cx, y: cy - 100), controlPoint1: NSPoint(x: cx + 86, y: cy - 10), controlPoint2: NSPoint(x: cx + 60, y: cy - 70))
    shield.curve(to: NSPoint(x: cx - 82, y: cy + 66), controlPoint1: NSPoint(x: cx - 60, y: cy - 70), controlPoint2: NSPoint(x: cx - 86, y: cy - 10))
    shield.curve(to: NSPoint(x: cx, y: cy + 98), controlPoint1: NSPoint(x: cx - 56, y: cy + 70), controlPoint2: NSPoint(x: cx - 30, y: cy + 80))
    shield.close()
    NSGradient(starting: rgb(40, 110, 205), ending: rgb(12, 50, 125))!.draw(in: shield, angle: -90)
    // Checkmark
    let check = NSBezierPath()
    check.move(to: NSPoint(x: cx - 42, y: cy + 4)); check.line(to: NSPoint(x: cx - 10, y: cy - 30)); check.line(to: NSPoint(x: cx + 46, y: cy + 40))
    check.lineWidth = 24; check.lineCapStyle = .round; check.lineJoinStyle = .round
    NSColor.white.setStroke(); check.stroke()

    NSGraphicsContext.restoreGraphicsState()
    return bitmap
}

var images: [[String: String]] = []
for size in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let name = "icon_\(size)x\(size)" + (scale == 2 ? "@2x" : "") + ".png"
        let png = draw(size * scale).representation(using: .png, properties: [:])!
        try png.write(to: iconset.appendingPathComponent(name))
        try png.write(to: appiconset.appendingPathComponent(name))
        images.append(["idiom": "mac", "size": "\(size)x\(size)", "scale": "\(scale)x", "filename": name])
    }
}
let contents: [String: Any] = ["images": images, "info": ["author": "xcode", "version": 1]]
try JSONSerialization.data(withJSONObject: contents, options: [.prettyPrinted, .sortedKeys]).write(to: appiconset.appendingPathComponent("Contents.json"))
try draw(1024).representation(using: .png, properties: [:])!.write(to: preview)
