#!/usr/bin/env python3
"""Loopback-only TEST server: speaks the plaintext stage of a protocol, then upgrades to TLS.
Usage: tls_server.py MODE CERTCHAIN KEY   (MODE: tls smtp imap pop3 ldap mysql smtp-nostarttls rdp-* winrm-http* registry-401 registry-200 registry-404)
Prints the bound port on stdout, serves connections until killed."""
import socket, ssl, sys, threading, struct
mode, chain, key = sys.argv[1], sys.argv[2], sys.argv[3]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(chain, key)
srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(8)
print(srv.getsockname()[1], flush=True)
def lines(f):
    return f.readline()
# Exact RDP request the client must send: TPKT, X.224 CR (no cookie), RDP_NEG_REQ SSL|HYBRID.
RDP_REQ = bytes.fromhex("03000013") + bytes.fromhex("0ee00000000000") + bytes.fromhex("0100080003000000")
def tpkt(x): return b"\x03\x00" + struct.pack(">H", 4 + len(x)) + x
CC = bytes.fromhex("0ed00000123400")
def recv_exact(c, n):
    b = b""
    while len(b) < n:
        d = c.recv(n - len(b))
        if not d: return b
        b += d
    return b
def rdp_stage(c):
    """Returns True when the TLS handshake should follow."""
    if recv_exact(c, 19) != RDP_REQ: return False
    kind = mode[4:]
    if kind == "hybrid": c.sendall(tpkt(CC + struct.pack("<BBHI", 2, 0x1F, 8, 2))); return True
    if kind == "ssl": c.sendall(tpkt(CC + struct.pack("<BBHI", 2, 0x00, 8, 1))); return True
    if kind == "hybridex": c.sendall(tpkt(CC + struct.pack("<BBHI", 2, 0, 8, 8))); return True
    if kind == "aad": c.sendall(tpkt(CC + struct.pack("<BBHI", 2, 0, 8, 0x10))); return True
    if kind == "split":
        import time
        for b in tpkt(CC + struct.pack("<BBHI", 2, 0, 8, 2)):
            c.sendall(bytes([b])); time.sleep(0.01)
        return True
    if kind == "rdpsec": c.sendall(tpkt(CC + struct.pack("<BBHI", 2, 0x00, 8, 0))); return False
    if kind.startswith("fail"): c.sendall(tpkt(CC + struct.pack("<BBHI", 3, 0, 8, int(kind[4:])))); return False
    if kind == "legacy": c.sendall(tpkt(bytes.fromhex("06d00000123400"))); return False
    if kind == "disconnect": c.sendall(tpkt(bytes.fromhex("0680000000000000"))); return False
    if kind == "http": c.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n"); return False
    if kind == "biglen": c.sendall(b"\x03\x00\xff\xff"); return False
    if kind == "inject": c.sendall(tpkt(CC + struct.pack("<BBHI", 2, 0, 8, 2)) + b"\x16junk"); return True
    return False
def winrm_http(c):
    head = b""
    while b"\r\n\r\n" not in head and len(head) < 8192:
        d = c.recv(1024)
        if not d: return
        head += d
    if not head.startswith(b"POST /wsman HTTP/1.1\r\n") or b"authorization" in head.lower(): return
    if mode == "winrm-http-noscheme":
        c.sendall(b"HTTP/1.1 401 \r\nContent-Length: 0\r\nConnection: close\r\n\r\n"); return
    if mode == "winrm-http-httpapi":
        c.sendall(b"HTTP/1.1 404 Not Found\r\nServer: Microsoft-HTTPAPI/2.0\r\nContent-Length: 0\r\n\r\n"); return
    if mode == "winrm-http-404":
        c.sendall(b"HTTP/1.1 404 Not Found\r\nServer: fixture\r\nContent-Length: 0\r\n\r\n"); return
    auth = b"WWW-Authenticate: Negotiate\r\nWWW-Authenticate: Kerberos\r\n" + (b"WWW-Authenticate: Basic realm=\"WSMAN\"\r\n" if mode == "winrm-http-basic" else b"")
    c.sendall(b"HTTP/1.1 401 \r\n" + auth + b"Server: Microsoft-HTTPAPI/2.0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
def registry(c):
    head = b""
    while b"\r\n\r\n" not in head and len(head) < 8192:
        d = c.recv(1024)
        if not d: return
        head += d
    if not head.startswith(b"GET /v2/ HTTP/1.1\r\n") or b"authorization" in head.lower(): return
    api = b"Docker-Distribution-Api-Version: registry/2.0\r\n"
    if mode == "registry-401":
        c.sendall(b"HTTP/1.1 401 Unauthorized\r\n" + api + b"WWW-Authenticate: Bearer realm=\"https://auth.example.test/token\",service=\"registry.example.test\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    elif mode == "registry-200":
        c.sendall(b"HTTP/1.1 200 OK\r\n" + api + b"Content-Length: 2\r\nConnection: close\r\n\r\n{}")
    else:
        c.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
def handle(c):
    try:
        c.settimeout(10); f = c.makefile("rb")
        if mode.startswith("winrm-http"):
            winrm_http(c); return
        if mode.startswith("rdp-") and not rdp_stage(c):
            return
        if mode == "silent":
            import time; time.sleep(30); return
        if mode == "smtp-inject":
            c.sendall(b"220 fixture ESMTP\r\n"); f.readline()
            c.sendall(b"250-fixture\r\n250 STARTTLS\r\n"); f.readline()
            c.sendall(b"220 Ready\r\n250 injected\r\n")
        elif mode == "smtp-454":
            c.sendall(b"220 fixture ESMTP\r\n"); f.readline()
            c.sendall(b"250-fixture\r\n250 STARTTLS\r\n"); f.readline()
            c.sendall(b"454 TLS not available\r\n"); return
        elif mode == "imap-no":
            c.sendall(b"* OK fixture IMAP\r\n"); f.readline(); c.sendall(b"a1 NO STARTTLS disabled\r\n"); return
        elif mode == "imap-bye":
            c.sendall(b"* OK fixture IMAP\r\n"); f.readline(); c.sendall(b"* BYE shutting down\r\n"); return
        elif mode == "pop3-err":
            c.sendall(b"+OK fixture POP3\r\n"); f.readline(); c.sendall(b"-ERR STLS not supported\r\n"); return
        elif mode in ("smtp", "smtp-nostarttls"):
            c.sendall(b"220 fixture ESMTP\r\n"); f.readline()
            c.sendall(b"250-fixture\r\n" + (b"250-STARTTLS\r\n" if mode == "smtp" else b"") + b"250 SIZE 1000\r\n")
            if mode != "smtp": return
            f.readline(); c.sendall(b"220 Ready to start TLS\r\n")
        elif mode == "imap":
            c.sendall(b"* OK fixture IMAP\r\n"); f.readline(); c.sendall(b"a1 OK Begin TLS\r\n")
        elif mode == "pop3":
            c.sendall(b"+OK fixture POP3\r\n"); f.readline(); c.sendall(b"+OK Begin TLS\r\n")
        elif mode == "ldap":
            req = c.recv(64)
            assert b"1.3.6.1.4.1.1466.20037" in req
            c.sendall(bytes([0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00]))
        elif mode == "mysql":
            payload = bytes([10]) + b"8.0.99-fixture\x00" + struct.pack("<I", 7) + b"abcdefgh" + b"\x00" + struct.pack("<H", 0xFFFF) + b"\x21" + b"\x02\x00" + b"\x00" * 13
            c.sendall(struct.pack("<I", len(payload))[:3] + b"\x00" + payload)
            c.recv(36)
        s = ctx.wrap_socket(c, server_side=True)
        if mode.startswith("registry-"):
            registry(s); return
        s.recv(1)
    except Exception:
        pass
    finally:
        try: c.close()
        except Exception: pass
while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
