"""Throwaway PKI and local HTTP servers for the M4 tests (example.test names, loopback only)."""

from __future__ import annotations

import datetime as dt
import http.server
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID

NOW = dt.datetime.now(dt.UTC).replace(microsecond=0)


@dataclass
class Issued:
    key: ec.EllipticCurvePrivateKey
    cert: x509.Certificate

    @property
    def pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)

    @property
    def der(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.DER)

    def key_pem(self) -> bytes:
        return self.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def issue(
    cn: str,
    issuer: Issued | None = None,
    *,
    ca: bool = False,
    ocsp_url: str | None = None,
    crl_url: str | None = None,
    ca_issuers: str | None = None,
    must_staple: bool = False,
    ocsp_signing: bool = False,
    extra: list[x509.ExtensionType] | None = None,
) -> Issued:
    key = ec.generate_private_key(ec.SECP256R1())
    b = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(issuer.cert.subject if issuer else _name(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - dt.timedelta(days=1))
        .not_valid_after(NOW + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if ca:
        b = b.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    else:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        eku = [ExtendedKeyUsageOID.OCSP_SIGNING] if ocsp_signing else [ExtendedKeyUsageOID.SERVER_AUTH]
        b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    if issuer:
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.key.public_key()), critical=False)
    aia = []
    if ocsp_url:
        aia.append(x509.AccessDescription(AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(ocsp_url)))
    if ca_issuers:
        aia.append(
            x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier(ca_issuers))
        )
    if aia:
        b = b.add_extension(x509.AuthorityInformationAccess(aia), critical=False)
    if crl_url:
        b = b.add_extension(
            x509.CRLDistributionPoints(
                [x509.DistributionPoint([x509.UniformResourceIdentifier(crl_url)], None, None, None)]
            ),
            critical=False,
        )
    if must_staple:
        b = b.add_extension(x509.TLSFeature([x509.TLSFeatureType.status_request]), critical=False)
    for e in extra or []:
        b = b.add_extension(e, critical=False)
    signer = issuer.key if issuer else key
    return Issued(key, b.sign(signer, hashes.SHA256()))


def ocsp_response(
    leaf: Issued,
    issuer: Issued,
    *,
    revoked: bool = False,
    signer: Issued | None = None,
    certs: list[x509.Certificate] | None = None,
) -> bytes:
    signer = signer or issuer
    b = ocsp.OCSPResponseBuilder().add_response(
        cert=leaf.cert,
        issuer=issuer.cert,
        algorithm=hashes.SHA1(),  # noqa: S303  (OCSP CertID default)
        cert_status=ocsp.OCSPCertStatus.REVOKED if revoked else ocsp.OCSPCertStatus.GOOD,
        this_update=NOW - dt.timedelta(minutes=1),
        next_update=NOW + dt.timedelta(hours=1),
        revocation_time=NOW - dt.timedelta(hours=1) if revoked else None,
        revocation_reason=x509.ReasonFlags.key_compromise if revoked else None,
    )
    b = b.responder_id(ocsp.OCSPResponderEncoding.HASH, signer.cert)
    if certs:
        b = b.certificates(certs)
    return b.sign(signer.key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def crl(
    issuer: Issued,
    revoked: list[x509.Certificate] = (),  # type: ignore[assignment]
    idp: x509.IssuingDistributionPoint | None = None,
) -> bytes:
    b = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer.cert.subject)
        .last_update(NOW - dt.timedelta(minutes=1))
        .next_update(NOW + dt.timedelta(days=1))
    )
    for c in revoked:
        b = b.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(c.serial_number)
            .revocation_date(NOW - dt.timedelta(hours=1))
            .add_extension(x509.CRLReason(x509.ReasonFlags.superseded), critical=False)
            .build()
        )
    if idp is not None:
        b = b.add_extension(idp, critical=True)
    return b.sign(issuer.key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


Route = Callable[[http.server.BaseHTTPRequestHandler, bytes], None]


@dataclass
class Web:
    port: int
    routes: dict[str, Route] = field(default_factory=dict)
    hits: list[str] = field(default_factory=list)

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def static(self, path: str, body: bytes, status: int = 200, headers: dict[str, str] | None = None) -> str:
        def r(h: http.server.BaseHTTPRequestHandler, _req: bytes) -> None:
            h.send_response(status)
            for k, v in (headers or {}).items():
                h.send_header(k, v)
            h.send_header("Content-Length", str(len(body)))
            h.end_headers()
            h.wfile.write(body)

        self.routes[path] = r
        return self.url(path)


@contextmanager
def web() -> Iterator[Web]:
    w = Web(0)

    class H(http.server.BaseHTTPRequestHandler):
        def _go(self) -> None:
            n = int(self.headers.get("Content-Length") or 0)
            req = self.rfile.read(n) if n else b""
            w.hits.append(f"{self.command} {self.path}")
            r = w.routes.get(self.path)
            if r is None:
                self.send_error(404)
                return
            with suppress(BrokenPipeError, ConnectionResetError):
                r(self, req)

        do_GET = do_POST = _go

        def log_message(self, *_a: object) -> None:
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    w.port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield w
    finally:
        srv.shutdown()
        srv.server_close()


def write(tmp: Path, name: str, data: bytes) -> Path:
    p = tmp / name
    p.write_bytes(data)
    return p


@contextmanager
def tls_server(ctx: ssl.SSLContext) -> Iterator[int]:
    """A loopback TLS server that completes handshakes and closes; yields its port."""
    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(16)
    lsock.settimeout(0.2)
    stop = threading.Event()

    def loop() -> None:
        while not stop.is_set():
            try:
                c, _ = lsock.accept()
            except (TimeoutError, OSError):
                continue
            c.settimeout(5)
            try:
                with ctx.wrap_socket(c, server_side=True) as s:
                    s.recv(1)
            except (ssl.SSLError, OSError):
                pass
            finally:
                c.close()

    th = threading.Thread(target=loop, daemon=True)
    th.start()
    try:
        yield lsock.getsockname()[1]
    finally:
        stop.set()
        th.join(2)
        lsock.close()


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_port(port: int, timeout: float = 10) -> None:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(port)
