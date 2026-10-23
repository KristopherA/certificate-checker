#!/usr/bin/env python3
"""Loopback-only plaintext HTTP listener for tests: prints its port, then "HOST <value>" for the one request it accepts,
and answers 401 with WWW-Authenticate: Negotiate. Binds 127.0.0.1 only; exits after one connection or 20 seconds."""
import socket, sys
s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(1); s.settimeout(20)
print(s.getsockname()[1], flush=True)
c, _ = s.accept(); c.settimeout(5); data = b""
while b"\r\n\r\n" not in data:
    chunk = c.recv(4096)
    if not chunk: break
    data += chunk
for line in data.decode("latin-1").split("\r\n"):
    if line.lower().startswith("host:"): print("HOST " + line[5:].strip(), flush=True)
c.sendall(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Negotiate\r\nServer: Microsoft-HTTPAPI/2.0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
c.close(); s.close()
